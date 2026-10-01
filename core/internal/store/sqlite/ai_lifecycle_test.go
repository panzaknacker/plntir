package sqlite

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"
)

func newAIRecordFixture(t *testing.T, store *Store, name string, now time.Time) AIRecordInput {
	t.Helper()
	account, err := store.CreateAccount(context.Background(), name, now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	deviceID := insertWipeTestDevice(t, store, account.ID, "AI-SERIAL-"+name, "unverified", now.Add(-time.Hour))
	digest := sha256.Sum256([]byte("complete encrypted chat " + name))
	return AIRecordInput{
		AccountID: account.ID, DeviceID: deviceID, Source: "codex-cli", Coverage: "full",
		CiphertextObjectKey: "ai/obj_0123456789abcdefghjkmnpqrstvwxyz",
		KMSEnvelope:         []byte("kms-ciphertext"), OfflineEnvelope: []byte(strings.Repeat("o", 64)), ContentSHA256: digest,
		ClientDeduplicationID: "ai:capture:" + strings.ReplaceAll(name, " ", "-"), CaptureVersion: 1,
		CaptureID: "cap_0123456789abcdefghjkmnpqrstvwxyz", FinalSegment: true,
		OccurredAt: now.Add(-time.Minute), Now: now,
	}
}

func TestAIIngestQueuesOnlyOpaqueMetadataAndIsIdempotent(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	now := time.Date(2026, 9, 5, 7, 0, 0, 0, time.UTC)
	input := newAIRecordFixture(t, store, "AI ingest", now)
	record, err := store.CreateAIRecord(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if !record.PurgeAfter.Equal(now.Add(7*24*time.Hour)) || !record.HistoryRetainUntil.Equal(now.Add(180*24*time.Hour)) || record.AnalysisState != "queued" {
		t.Fatalf("wrong AI retention/state: %+v", record)
	}
	repeated, err := store.CreateAIRecord(ctx, input)
	if err != nil || repeated.ID != record.ID {
		t.Fatalf("idempotent capture failed: %+v %v", repeated, err)
	}
	changed := input
	changed.Coverage = "partial"
	if _, err := store.CreateAIRecord(ctx, changed); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("conflicting capture dedupe accepted: %v", err)
	}
	var jobPayload, auditDetails string
	if err := store.db.QueryRow("SELECT payload_json FROM durable_jobs WHERE deduplication_id = ?", "ai:analyze:"+record.ID).Scan(&jobPayload); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow("SELECT details_json FROM audit_log WHERE action = 'ai.record.ingest'").Scan(&auditDetails); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"complete encrypted chat", "kms-ciphertext", input.CiphertextObjectKey} {
		if strings.Contains(jobPayload+auditDetails, secret) {
			t.Fatalf("queue/audit leaked AI content metadata %q", secret)
		}
	}
}

func TestAIRecordSegmentsRequireAnUnbrokenNonFinalPredecessor(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	now := time.Date(2026, 9, 5, 7, 30, 0, 0, time.UTC)
	firstInput := newAIRecordFixture(t, store, "AI segment chain", now)
	firstInput.FinalSegment = false
	first, err := store.CreateAIRecord(ctx, firstInput)
	if err != nil {
		t.Fatal(err)
	}

	missing := firstInput
	missing.ClientDeduplicationID = "ai:capture:missing-predecessor"
	missing.CiphertextObjectKey = "ai/obj_2123456789abcdefghjkmnpqrstvwxyz"
	missing.ContentSHA256 = sha256.Sum256([]byte("missing predecessor"))
	missing.SegmentIndex = 2
	missing.FinalSegment = true
	missing.PreviousSegmentSHA256 = append([]byte(nil), first.ContentSHA256[:]...)
	missing.Now = now.Add(time.Minute)
	if _, err := store.CreateAIRecord(ctx, missing); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("segment with a missing predecessor was accepted: %v", err)
	}

	wrongHash := firstInput
	wrongHash.ClientDeduplicationID = "ai:capture:wrong-predecessor"
	wrongHash.CiphertextObjectKey = "ai/obj_3123456789abcdefghjkmnpqrstvwxyz"
	wrongHash.ContentSHA256 = sha256.Sum256([]byte("wrong predecessor hash"))
	wrongHash.SegmentIndex = 1
	wrongHash.FinalSegment = true
	wrongHash.PreviousSegmentSHA256 = make([]byte, sha256.Size)
	wrongHash.Now = now.Add(2 * time.Minute)
	if _, err := store.CreateAIRecord(ctx, wrongHash); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("segment with the wrong predecessor hash was accepted: %v", err)
	}

	secondInput := firstInput
	secondInput.ClientDeduplicationID = "ai:capture:valid-second-segment"
	secondInput.CiphertextObjectKey = "ai/obj_4123456789abcdefghjkmnpqrstvwxyz"
	secondInput.ContentSHA256 = sha256.Sum256([]byte("valid second encrypted segment"))
	secondInput.SegmentIndex = 1
	secondInput.FinalSegment = true
	secondInput.PreviousSegmentSHA256 = append([]byte(nil), first.ContentSHA256[:]...)
	secondInput.Now = now.Add(3 * time.Minute)
	second, err := store.CreateAIRecord(ctx, secondInput)
	if err != nil || second.SegmentIndex != 1 || !second.FinalSegment ||
		!bytes.Equal(second.PreviousSegmentSHA256, first.ContentSHA256[:]) {
		t.Fatalf("valid second segment rejected: %+v %v", second, err)
	}

	appendAfterFinal := secondInput
	appendAfterFinal.ClientDeduplicationID = "ai:capture:after-final"
	appendAfterFinal.CiphertextObjectKey = "ai/obj_5123456789abcdefghjkmnpqrstvwxyz"
	appendAfterFinal.ContentSHA256 = sha256.Sum256([]byte("must not follow final"))
	appendAfterFinal.SegmentIndex = 2
	appendAfterFinal.PreviousSegmentSHA256 = append([]byte(nil), second.ContentSHA256[:]...)
	appendAfterFinal.Now = now.Add(4 * time.Minute)
	if _, err := store.CreateAIRecord(ctx, appendAfterFinal); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("segment appended after final predecessor: %v", err)
	}
}

func TestLatePromptInjectionBlocksOnlyTheNextSupportedActionUntilPasskeyConfirmation(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	now := time.Date(2026, 9, 5, 8, 0, 0, 0, time.UTC)
	input := newAIRecordFixture(t, store, "AI warning", now)
	record, err := store.CreateAIRecord(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RequireAIActionClear(ctx, input.AccountID, input.DeviceID); err != nil {
		t.Fatalf("action blocked before a finding: %v", err)
	}
	lease, err := store.LeaseNextAIAnalysis(ctx, "analyzer-1", 5*time.Minute, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	result := AIAnalysisResult{JobID: lease.JobID, RecordID: record.ID, WorkerID: "analyzer-1",
		ClassifierVersion: "classifier-1.0.0", RulesVersion: "rules-20260905",
		Findings: []AIFindingInput{{Kind: "prompt-injection", Severity: "high", SummaryCode: "prompt-injection.detected"}},
		Now:      now.Add(2 * time.Minute)}
	completion, err := store.CompleteAIAnalysis(ctx, result)
	if err != nil || completion.ActionHoldCount != 1 || completion.FindingCount != 1 {
		t.Fatalf("analysis completion failed: %+v %v", completion, err)
	}
	repeated, err := store.CompleteAIAnalysis(ctx, result)
	if err != nil || !repeated.Duplicate {
		t.Fatalf("analysis replay was not idempotent: %+v %v", repeated, err)
	}
	if err := store.RequireAIActionClear(ctx, input.AccountID, input.DeviceID); !errors.Is(err, ErrAIConfirmationRequired) {
		t.Fatalf("late prompt injection did not block supported action: %v", err)
	}
	var holdID string
	if err := store.db.QueryRow("SELECT id FROM ai_action_holds WHERE record_id = ?", record.ID).Scan(&holdID); err != nil {
		t.Fatal(err)
	}
	confirmation := AIActionConfirmation{HoldID: holdID, AccountID: input.AccountID, DeviceID: input.DeviceID,
		AssertionVerified: true, AssertionID: "passkey-assertion-1", VerifiedAt: now.Add(3 * time.Minute), Now: now.Add(3 * time.Minute)}
	stale := confirmation
	stale.VerifiedAt = now.Add(-11 * time.Minute)
	if err := store.ConfirmAIActionHold(ctx, stale); !errors.Is(err, ErrAIConfirmationRequired) {
		t.Fatalf("stale confirmation was accepted: %v", err)
	}
	if err := store.ConfirmAIActionHold(ctx, confirmation); err != nil {
		t.Fatal(err)
	}
	if err := store.RequireAIActionClear(ctx, input.AccountID, input.DeviceID); err != nil {
		t.Fatalf("confirmed warning still blocked action: %v", err)
	}
}

func TestAnalyzerFailureIsSilentAndRetryable(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	now := time.Date(2026, 9, 5, 9, 0, 0, 0, time.UTC)
	input := newAIRecordFixture(t, store, "AI retry", now)
	record, err := store.CreateAIRecord(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := store.LeaseNextAIAnalysis(ctx, "analyzer-retry", 5*time.Minute, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RetryAIAnalysis(ctx, lease.JobID, record.ID, "analyzer-retry", "classifier unavailable\nsecret omitted",
		now.Add(5*time.Minute), now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	var state, failure string
	if err := store.db.QueryRow(`SELECT r.analysis_state, j.last_error FROM ai_records r JOIN durable_jobs j
		ON j.deduplication_id = 'ai:analyze:' || r.id WHERE r.id = ?`, record.ID).Scan(&state, &failure); err != nil {
		t.Fatal(err)
	}
	if state != "queued" || strings.ContainsAny(failure, "\r\n") {
		t.Fatalf("retry state/error unsafe: state=%s failure=%q", state, failure)
	}
	if err := store.RequireAIActionClear(ctx, input.AccountID, input.DeviceID); err != nil {
		t.Fatalf("analyzer outage became a user-facing action hold: %v", err)
	}
}

func TestRawReadNeedsFreshMasteradminWebAuthnAndSevenDayPurgeDestroysBothWraps(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	now := time.Date(2026, 9, 5, 10, 0, 0, 0, time.UTC)
	input := newAIRecordFixture(t, store, "AI purge", now)
	record, err := store.CreateAIRecord(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	request := AIRawReadRequest{RecordID: record.ID, AdminActor: "masteradmin", Reason: "Investigating incident INC-42",
		Proof: AIAdminProof{IsMasterAdmin: true, WebAuthnVerified: true, AssertionID: "webauthn-stepup-1", VerifiedAt: now}, Now: now}
	withoutProof := request
	withoutProof.Proof.WebAuthnVerified = false
	if _, err := store.AuthorizeAIRawRead(ctx, withoutProof); !errors.Is(err, ErrAIRawUnavailable) {
		t.Fatalf("raw read without WebAuthn was accepted: %v", err)
	}
	grant, err := store.AuthorizeAIRawRead(ctx, request)
	if err != nil || grant.CiphertextObjectKey != input.CiphertextObjectKey || !grant.ExpiresAt.Equal(record.PurgeAfter) {
		t.Fatalf("valid raw grant failed: %+v %v", grant, err)
	}
	if count, err := store.PurgeExpiredAIRaw(ctx, record.PurgeAfter.Add(-time.Nanosecond)); err != nil || count != 0 {
		t.Fatalf("raw data purged early: count=%d err=%v", count, err)
	}
	count, err := store.PurgeExpiredAIRaw(ctx, record.PurgeAfter)
	if err != nil || count != 1 {
		t.Fatalf("raw purge failed at deadline: count=%d err=%v", count, err)
	}
	if _, err := store.AuthorizeAIRawRead(ctx, request); !errors.Is(err, ErrAIRawUnavailable) {
		t.Fatalf("destroyed raw record remained readable: %v", err)
	}
	var kms, offline []byte
	var state, payload string
	if err := store.db.QueryRow("SELECT kms_envelope, offline_envelope, analysis_state FROM ai_records WHERE id = ?", record.ID).Scan(&kms, &offline, &state); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow("SELECT payload_json FROM outbox WHERE deduplication_id = ?", "ai:delete:"+record.ID).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if state != "purged" || bytesNotZero(kms) || bytesNotZero(offline) || !strings.Contains(payload, input.CiphertextObjectKey) {
		t.Fatalf("crypto purge incomplete: state=%s kms=%x offline=%x payload=%s", state, kms, offline, payload)
	}
	if count, err := store.PurgeExpiredAIHistory(ctx, record.HistoryRetainUntil.Add(-time.Nanosecond)); err != nil || count != 0 {
		t.Fatalf("history purged early: count=%d err=%v", count, err)
	}
	if count, err := store.PurgeExpiredAIHistory(ctx, record.HistoryRetainUntil); err != nil || count != 1 {
		t.Fatalf("history purge failed: count=%d err=%v", count, err)
	}
	var remaining int
	if err := store.db.QueryRow("SELECT count(*) FROM ai_records WHERE id = ?", record.ID).Scan(&remaining); err != nil || remaining != 0 {
		t.Fatalf("expired AI history remains: %d %v", remaining, err)
	}
	if err := store.VerifyAuditChain(ctx); err != nil {
		t.Fatal(err)
	}
}

func bytesNotZero(value []byte) bool {
	for _, octet := range value {
		if octet != 0 {
			return true
		}
	}
	return false
}
