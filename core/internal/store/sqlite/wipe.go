package sqlite

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"plntir/core/internal/idgen"
)

var (
	ErrWipeUnavailable = errors.New("verified wipe capability and exact device identity are required")
	ErrWipeIrrevocable = errors.New("wipe has already been handed to MDM and cannot be cancelled")
)

type WipeAuthorization struct {
	ActionPasswordVerified bool
	FIDOAssertionVerified  bool
	ActionVerificationID   string
	FIDOKeyID              string
	AuthenticatedAt        time.Time
}

type DeviceWipeRequest struct {
	DeviceID        string
	TypedDeviceID   string
	TypedSerial     string
	ExpectedVersion int64
	RequestedBy     string
	Authorization   WipeAuthorization
	Now             time.Time
}

type WipeJob struct {
	ID            string
	DeviceID      string
	State         string
	RequestedBy   string
	RequestedAt   time.Time
	HandedToMDMAt *time.Time
	CompletedAt   *time.Time
	MDMCommandID  string
	LastError     string
	DeviceVersion int64
}

func (s *Store) RequestSingleDeviceWipe(ctx context.Context, request DeviceWipeRequest) (WipeJob, error) {
	request.Now = normalizedTime(request.Now)
	if !validWipeAuthorization(request.Authorization, request.Now) || strings.TrimSpace(request.RequestedBy) == "" ||
		request.DeviceID == "" || request.ExpectedVersion < 1 || len(request.TypedSerial) < 4 || len(request.TypedSerial) > 128 ||
		strings.ContainsAny(request.TypedSerial, "\x00\r\n") {
		return WipeJob{}, ErrWipeUnavailable
	}
	if !constantStringEqual(request.DeviceID, request.TypedDeviceID) {
		return WipeJob{}, ErrWipeUnavailable
	}
	wipeID, err := idgen.New("wipe")
	if err != nil {
		return WipeJob{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return WipeJob{}, err
	}
	defer tx.Rollback()
	var serialNumber, managementState, wipeState, deviceState string
	var deviceVersion int64
	err = tx.QueryRowContext(ctx, `SELECT serial_number, management_state, wipe_state, state, version
		FROM devices WHERE id = ?`, request.DeviceID).
		Scan(&serialNumber, &managementState, &wipeState, &deviceState, &deviceVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return WipeJob{}, ErrWipeUnavailable
	}
	if err != nil {
		return WipeJob{}, err
	}
	if !constantStringEqual(serialNumber, request.TypedSerial) || managementState != "verified" || wipeState != "verified" ||
		(deviceState != "active" && deviceState != "suspended") || deviceVersion != request.ExpectedVersion {
		return WipeJob{}, ErrWipeUnavailable
	}
	var existing int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM wipe_jobs WHERE device_id = ?
		AND state IN ('pending_local', 'handed_to_mdm', 'acknowledged')`, request.DeviceID).Scan(&existing); err != nil {
		return WipeJob{}, err
	}
	if existing != 0 {
		return WipeJob{}, ErrInvalidState
	}
	stamp := request.Now.Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `INSERT INTO wipe_jobs
		(id, device_id, requested_by, typed_device_id, typed_serial_number, state, requested_at)
		VALUES (?, ?, ?, ?, ?, 'pending_local', ?)`, wipeID, request.DeviceID, request.RequestedBy,
		request.TypedDeviceID, request.TypedSerial, stamp); err != nil {
		if constraintContains(err, "one_live_wipe_per_device") || constraintContains(err, "wipe_jobs.device_id") {
			return WipeJob{}, ErrInvalidState
		}
		return WipeJob{}, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE devices SET reassignment_blocked = 1, version = version + 1,
		updated_at = ? WHERE id = ? AND version = ?`, stamp, request.DeviceID, request.ExpectedVersion)
	if err != nil {
		return WipeJob{}, err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return WipeJob{}, ErrVersionConflict
	}
	payload, _ := json.Marshal(map[string]any{"wipe_job_id": wipeID, "device_id": request.DeviceID, "requested_at": stamp})
	for _, event := range []struct{ topic, dedupe string }{
		{"wipe.requested", "wipe:dispatch:" + wipeID},
		{"alert.email", "wipe:email:" + wipeID},
		{"alert.sms", "wipe:sms:" + wipeID},
	} {
		if _, err := enqueueOutboxTx(ctx, tx, event.topic, event.dedupe, payload, request.Now); err != nil {
			return WipeJob{}, err
		}
	}
	if _, err := appendAuditTx(ctx, tx, request.RequestedBy, "device.wipe.request", request.DeviceID, true,
		map[string]any{"wipe_job_id": wipeID, "dual_proof": true}, request.Now); err != nil {
		return WipeJob{}, err
	}
	if err := tx.Commit(); err != nil {
		return WipeJob{}, err
	}
	return WipeJob{ID: wipeID, DeviceID: request.DeviceID, State: "pending_local",
		RequestedBy: request.RequestedBy, RequestedAt: request.Now, DeviceVersion: request.ExpectedVersion + 1}, nil
}

func (s *Store) RecordPendingWipeFailure(ctx context.Context, wipeJobID, workerID, failure string, now time.Time) error {
	now = normalizedTime(now)
	if !safeWorkerID.MatchString(workerID) || strings.TrimSpace(failure) == "" {
		return errors.New("wipe failure report is invalid")
	}
	failure = sanitizeJobError(failure)
	result, err := s.db.ExecContext(ctx, `UPDATE wipe_jobs SET last_error = ?
		WHERE id = ? AND state = 'pending_local'`, failure, wipeJobID)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return ErrResourceNotFound
	}
	return nil
}

func (s *Store) HandWipeToMDM(ctx context.Context, wipeJobID, deviceID, mdmCommandID, workerID string, now time.Time) (WipeJob, error) {
	now = normalizedTime(now)
	if !safeWorkerID.MatchString(workerID) || mdmCommandID == "" || len(mdmCommandID) > 512 || strings.ContainsAny(mdmCommandID, "\x00\r\n") {
		return WipeJob{}, errors.New("MDM wipe handoff is invalid")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return WipeJob{}, err
	}
	defer tx.Rollback()
	job, err := wipeJobByIDTx(ctx, tx, wipeJobID)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && job.DeviceID != deviceID) {
		return WipeJob{}, ErrResourceNotFound
	}
	if err != nil {
		return WipeJob{}, err
	}
	if job.State == "handed_to_mdm" && job.MDMCommandID == mdmCommandID {
		if err := tx.Commit(); err != nil {
			return WipeJob{}, err
		}
		return job, nil
	}
	if job.State != "pending_local" || job.MDMCommandID != "" {
		return WipeJob{}, ErrWipeIrrevocable
	}
	stamp := now.Format(time.RFC3339Nano)
	result, err := tx.ExecContext(ctx, `UPDATE wipe_jobs SET state = 'handed_to_mdm', handed_to_mdm_at = ?,
		mdm_command_id = ?, last_error = NULL WHERE id = ? AND device_id = ? AND state = 'pending_local'
		AND mdm_command_id IS NULL`, stamp, mdmCommandID, wipeJobID, deviceID)
	if err != nil {
		return WipeJob{}, err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return WipeJob{}, ErrVersionConflict
	}
	if _, err := tx.ExecContext(ctx, `UPDATE devices SET version = version + 1, updated_at = ?
		WHERE id = ? AND reassignment_blocked = 1`, stamp, deviceID); err != nil {
		return WipeJob{}, err
	}
	if _, err := appendAuditTx(ctx, tx, "mdm-bridge:"+workerID, "device.wipe.handed-to-mdm", deviceID, true,
		map[string]any{"wipe_job_id": wipeJobID}, now); err != nil {
		return WipeJob{}, err
	}
	if err := tx.Commit(); err != nil {
		return WipeJob{}, err
	}
	job.State, job.MDMCommandID, job.HandedToMDMAt = "handed_to_mdm", mdmCommandID, &now
	job.DeviceVersion++
	return job, nil
}

func (s *Store) CancelPendingWipe(ctx context.Context, wipeJobID, adminActor, reason string, now time.Time) error {
	now = normalizedTime(now)
	reason = sanitizeJobError(reason)
	if strings.TrimSpace(adminActor) == "" || len(reason) < 8 || len(reason) > 500 {
		return errors.New("wipe cancellation is invalid")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	job, err := wipeJobByIDTx(ctx, tx, wipeJobID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrResourceNotFound
	}
	if err != nil {
		return err
	}
	if job.State != "pending_local" {
		if job.State == "handed_to_mdm" || job.State == "acknowledged" || job.State == "executed" {
			return ErrWipeIrrevocable
		}
		return ErrInvalidState
	}
	stamp := now.Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `UPDATE wipe_jobs SET state = 'cancelled', completed_at = ?
		WHERE id = ? AND state = 'pending_local'`, stamp, wipeJobID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE devices SET reassignment_blocked = 0, version = version + 1,
		updated_at = ? WHERE id = ? AND reassignment_blocked = 1`, stamp, job.DeviceID); err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]any{"wipe_job_id": wipeJobID, "device_id": job.DeviceID, "cancelled_at": stamp})
	for _, event := range []struct{ topic, dedupe string }{
		{"alert.email", "wipe:cancel:email:" + wipeJobID}, {"alert.sms", "wipe:cancel:sms:" + wipeJobID},
	} {
		if _, err := enqueueOutboxTx(ctx, tx, event.topic, event.dedupe, payload, now); err != nil {
			return err
		}
	}
	if _, err := appendAuditTx(ctx, tx, adminActor, "device.wipe.cancel", job.DeviceID, true,
		map[string]any{"wipe_job_id": wipeJobID, "reason": reason}, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ApplyMDMWipeState(ctx context.Context, wipeJobID, mdmCommandID, state, workerID, failure string, now time.Time) error {
	now = normalizedTime(now)
	if !safeWorkerID.MatchString(workerID) || (state != "acknowledged" && state != "executed" && state != "failed") {
		return errors.New("MDM wipe state is invalid")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	job, err := wipeJobByIDTx(ctx, tx, wipeJobID)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !constantStringEqual(job.MDMCommandID, mdmCommandID)) {
		return ErrResourceNotFound
	}
	if err != nil {
		return err
	}
	if job.State == state {
		return tx.Commit()
	}
	allowed := (job.State == "handed_to_mdm" && (state == "acknowledged" || state == "failed")) ||
		(job.State == "acknowledged" && (state == "executed" || state == "failed"))
	if !allowed {
		return ErrInvalidState
	}
	failure = sanitizeJobError(failure)
	if state == "failed" && failure == "" {
		return errors.New("failed wipe requires a reason")
	}
	stamp := now.Format(time.RFC3339Nano)
	completed := any(nil)
	if state == "executed" || state == "failed" {
		completed = stamp
	}
	result, err := tx.ExecContext(ctx, `UPDATE wipe_jobs SET state = ?, completed_at = ?, last_error = NULLIF(?, '')
		WHERE id = ? AND mdm_command_id = ? AND state = ?`, state, completed, failure, wipeJobID, mdmCommandID, job.State)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return ErrVersionConflict
	}
	if state == "executed" {
		if _, err := tx.ExecContext(ctx, `UPDATE devices SET state = 'retired', reassignment_blocked = 0,
			version = version + 1, updated_at = ? WHERE id = ?`, stamp, job.DeviceID); err != nil {
			return err
		}
	} else if state == "failed" {
		if _, err := tx.ExecContext(ctx, `UPDATE devices SET reassignment_blocked = 0,
			version = version + 1, updated_at = ? WHERE id = ?`, stamp, job.DeviceID); err != nil {
			return err
		}
	}
	if _, err := appendAuditTx(ctx, tx, "mdm-bridge:"+workerID, "device.wipe."+state, job.DeviceID, true,
		map[string]any{"wipe_job_id": wipeJobID}, now); err != nil {
		return err
	}
	return tx.Commit()
}

func wipeJobByIDTx(ctx context.Context, tx *sql.Tx, wipeJobID string) (WipeJob, error) {
	var job WipeJob
	var requestedAt string
	var handed, completed, command, lastError sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT w.id, w.device_id, w.state, w.requested_by, w.requested_at,
		w.handed_to_mdm_at, w.completed_at, w.mdm_command_id, w.last_error, d.version
		FROM wipe_jobs w JOIN devices d ON d.id = w.device_id WHERE w.id = ?`, wipeJobID).
		Scan(&job.ID, &job.DeviceID, &job.State, &job.RequestedBy, &requestedAt, &handed, &completed,
			&command, &lastError, &job.DeviceVersion)
	if err != nil {
		return WipeJob{}, err
	}
	job.MDMCommandID, job.LastError = command.String, lastError.String
	job.RequestedAt, err = time.Parse(time.RFC3339Nano, requestedAt)
	if err != nil {
		return WipeJob{}, err
	}
	if handed.Valid {
		stamp, parseErr := time.Parse(time.RFC3339Nano, handed.String)
		if parseErr != nil {
			return WipeJob{}, parseErr
		}
		job.HandedToMDMAt = &stamp
	}
	if completed.Valid {
		stamp, parseErr := time.Parse(time.RFC3339Nano, completed.String)
		if parseErr != nil {
			return WipeJob{}, parseErr
		}
		job.CompletedAt = &stamp
	}
	return job, nil
}

func validWipeAuthorization(authorization WipeAuthorization, now time.Time) bool {
	if !authorization.ActionPasswordVerified || !authorization.FIDOAssertionVerified ||
		authorization.ActionVerificationID == "" || authorization.FIDOKeyID == "" || authorization.AuthenticatedAt.IsZero() {
		return false
	}
	age := now.Sub(authorization.AuthenticatedAt.UTC())
	return age >= -30*time.Second && age <= 10*time.Minute
}

func constantStringEqual(first, second string) bool {
	return subtle.ConstantTimeCompare([]byte(first), []byte(second)) == 1
}
