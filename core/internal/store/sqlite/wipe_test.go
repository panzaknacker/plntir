package sqlite

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"plntir/core/internal/idgen"
)

func insertWipeTestDevice(t *testing.T, store *Store, accountID, serial, wipeState string, now time.Time) string {
	t.Helper()
	deviceID, err := idgen.New("dev")
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := sha256.Sum256([]byte(serial))
	stamp := now.Format(time.RFC3339Nano)
	_, err = store.db.Exec(`INSERT INTO devices
		(id, account_id, display_name, platform, serial_number, serial_fingerprint, warp_device_id,
		management_state, enrollment_type, posture_state, wipe_state, state, version, created_at, updated_at)
		VALUES (?, ?, 'Wipe test Mac', 'macos', ?, ?, ?, 'verified', 'user-enrollment', 'passing', ?, 'active', 1, ?, ?)`,
		deviceID, accountID, serial, fingerprint[:], "warp-"+deviceID, wipeState, stamp, stamp)
	if err != nil {
		t.Fatal(err)
	}
	return deviceID
}

func validTestWipeRequest(deviceID, serial string, now time.Time) DeviceWipeRequest {
	return DeviceWipeRequest{
		DeviceID: deviceID, TypedDeviceID: deviceID, TypedSerial: serial, ExpectedVersion: 1,
		RequestedBy: "masteradmin", Now: now,
		Authorization: WipeAuthorization{ActionPasswordVerified: true, FIDOAssertionVerified: true,
			ActionVerificationID: "action-check-001", FIDOKeyID: "hardware-key-a", AuthenticatedAt: now},
	}
}

func TestWipeRequiresExactIdentityVerifiedCapabilityAndFreshDualProof(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	now := time.Date(2026, 9, 4, 21, 0, 0, 0, time.UTC)
	account, _ := store.CreateAccount(ctx, "Wipe admin target", now)
	serial := "C02-EXACT-SERIAL"
	deviceID := insertWipeTestDevice(t, store, account.ID, serial, "unverified", now)
	request := validTestWipeRequest(deviceID, serial, now.Add(time.Minute))
	if _, err := store.RequestSingleDeviceWipe(ctx, request); !errors.Is(err, ErrWipeUnavailable) {
		t.Fatalf("unverified wipe capability was accepted: %v", err)
	}
	if _, err := store.db.Exec("UPDATE devices SET wipe_state = 'verified' WHERE id = ?", deviceID); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*DeviceWipeRequest){
		"device id":       func(value *DeviceWipeRequest) { value.TypedDeviceID += "x" },
		"serial":          func(value *DeviceWipeRequest) { value.TypedSerial += "x" },
		"action password": func(value *DeviceWipeRequest) { value.Authorization.ActionPasswordVerified = false },
		"FIDO":            func(value *DeviceWipeRequest) { value.Authorization.FIDOAssertionVerified = false },
		"freshness":       func(value *DeviceWipeRequest) { value.Authorization.AuthenticatedAt = now.Add(-11 * time.Minute) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := request
			mutate(&changed)
			if _, err := store.RequestSingleDeviceWipe(ctx, changed); !errors.Is(err, ErrWipeUnavailable) {
				t.Fatalf("invalid request was accepted: %v", err)
			}
		})
	}
	var jobs int
	if err := store.db.QueryRow("SELECT count(*) FROM wipe_jobs").Scan(&jobs); err != nil || jobs != 0 {
		t.Fatalf("failed proof left a wipe job: %d %v", jobs, err)
	}
}

func TestPendingWipeBlocksReassignmentButCanBeCancelledBeforeHandoff(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	now := time.Date(2026, 9, 4, 22, 0, 0, 0, time.UTC)
	account, _ := store.CreateAccount(ctx, "Offline wipe", now)
	serial := "C02-OFFLINE-WIPE"
	deviceID := insertWipeTestDevice(t, store, account.ID, serial, "verified", now)
	job, err := store.RequestSingleDeviceWipe(ctx, validTestWipeRequest(deviceID, serial, now.Add(time.Minute)))
	if err != nil || job.State != "pending_local" {
		t.Fatalf("wipe request failed: %+v %v", job, err)
	}
	if err := store.RecordPendingWipeFailure(ctx, job.ID, "mdm-bridge-1", "device offline\nwill retry", now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	var blocked int
	var state, failure string
	if err := store.db.QueryRow("SELECT reassignment_blocked FROM devices WHERE id = ?", deviceID).Scan(&blocked); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow("SELECT state, last_error FROM wipe_jobs WHERE id = ?", job.ID).Scan(&state, &failure); err != nil {
		t.Fatal(err)
	}
	if blocked != 1 || state != "pending_local" || strings.ContainsAny(failure, "\r\n") {
		t.Fatalf("offline wipe did not remain safely pending: blocked=%d state=%s failure=%q", blocked, state, failure)
	}
	var alertCount, dispatchCount int
	if err := store.db.QueryRow("SELECT count(*) FROM outbox WHERE topic IN ('alert.email', 'alert.sms')").Scan(&alertCount); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow("SELECT count(*) FROM outbox WHERE topic = 'wipe.requested'").Scan(&dispatchCount); err != nil {
		t.Fatal(err)
	}
	if alertCount != 2 || dispatchCount != 1 {
		t.Fatalf("wipe did not atomically queue both alerts and dispatch: alerts=%d dispatch=%d", alertCount, dispatchCount)
	}
	if err := store.CancelPendingWipe(ctx, job.ID, "masteradmin", "Device was recovered before MDM pickup", now.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow("SELECT reassignment_blocked FROM devices WHERE id = ?", deviceID).Scan(&blocked); err != nil || blocked != 0 {
		t.Fatalf("cancelled local wipe kept reassignment blocked: %d %v", blocked, err)
	}
}

func TestWipeIsIrrevocableAfterMDMHandoffAndExecutesOnce(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	now := time.Date(2026, 9, 4, 23, 0, 0, 0, time.UTC)
	account, _ := store.CreateAccount(ctx, "Handed wipe", now)
	serial := "C02-HANDED-WIPE"
	deviceID := insertWipeTestDevice(t, store, account.ID, serial, "verified", now)
	job, err := store.RequestSingleDeviceWipe(ctx, validTestWipeRequest(deviceID, serial, now.Add(time.Minute)))
	if err != nil {
		t.Fatal(err)
	}
	handed, err := store.HandWipeToMDM(ctx, job.ID, deviceID, "fleet-command-opaque", "mdm-bridge-1", now.Add(2*time.Minute))
	if err != nil || handed.State != "handed_to_mdm" {
		t.Fatalf("MDM handoff failed: %+v %v", handed, err)
	}
	repeated, err := store.HandWipeToMDM(ctx, job.ID, deviceID, "fleet-command-opaque", "mdm-bridge-1", now.Add(3*time.Minute))
	if err != nil || repeated.MDMCommandID != handed.MDMCommandID {
		t.Fatalf("idempotent MDM handoff failed: %+v %v", repeated, err)
	}
	if err := store.CancelPendingWipe(ctx, job.ID, "masteradmin", "Attempted cancellation after provider handoff", now.Add(4*time.Minute)); !errors.Is(err, ErrWipeIrrevocable) {
		t.Fatalf("handed wipe was cancellable: %v", err)
	}
	if err := store.ApplyMDMWipeState(ctx, job.ID, "wrong-command", "acknowledged", "mdm-bridge-1", "", now.Add(5*time.Minute)); !errors.Is(err, ErrResourceNotFound) {
		t.Fatalf("wrong MDM command updated wipe: %v", err)
	}
	if err := store.ApplyMDMWipeState(ctx, job.ID, handed.MDMCommandID, "acknowledged", "mdm-bridge-1", "", now.Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := store.ApplyMDMWipeState(ctx, job.ID, handed.MDMCommandID, "executed", "mdm-bridge-1", "", now.Add(6*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := store.ApplyMDMWipeState(ctx, job.ID, handed.MDMCommandID, "executed", "mdm-bridge-1", "", now.Add(7*time.Minute)); err != nil {
		t.Fatalf("duplicate execution acknowledgement was not idempotent: %v", err)
	}
	var deviceState string
	var blocked int
	if err := store.db.QueryRow("SELECT state, reassignment_blocked FROM devices WHERE id = ?", deviceID).Scan(&deviceState, &blocked); err != nil {
		t.Fatal(err)
	}
	if deviceState != "retired" || blocked != 0 {
		t.Fatalf("executed wipe left unsafe device state: state=%s blocked=%d", deviceState, blocked)
	}
	var serialized string
	if err := store.db.QueryRow("SELECT group_concat(payload_json, '') FROM outbox").Scan(&serialized); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(serialized, serial) || strings.Contains(serialized, "action-check-001") {
		t.Fatal("wipe alerts or dispatch leaked serial/proof identifiers")
	}
	if err := store.VerifyAuditChain(ctx); err != nil {
		t.Fatal(err)
	}
}
