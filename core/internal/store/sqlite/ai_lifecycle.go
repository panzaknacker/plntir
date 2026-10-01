package sqlite

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"plntir/core/internal/idgen"
)

const (
	aiRawRetention     = 7 * 24 * time.Hour
	aiHistoryRetention = 180 * 24 * time.Hour
)

var (
	ErrAIRawUnavailable       = errors.New("AI raw record is unavailable")
	ErrAIConfirmationRequired = errors.New("passkey confirmation is required before the next supported AI action")
	aiObjectKey               = regexp.MustCompile(`^ai/obj_[0-9a-hjkmnp-tv-z]{32}$`)
	aiReleaseToken            = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:+/-]{0,127}$`)
	aiFindingCode             = regexp.MustCompile(`^[a-z][a-z0-9.-]{0,127}$`)
)

type AIRecordInput struct {
	AccountID             string
	DeviceID              string
	Source                string
	Coverage              string
	CiphertextObjectKey   string
	KMSEnvelope           []byte
	OfflineEnvelope       []byte
	ContentSHA256         [sha256.Size]byte
	ClientDeduplicationID string
	CaptureID             string
	SegmentIndex          int64
	FinalSegment          bool
	PreviousSegmentSHA256 []byte
	CaptureVersion        int64
	OccurredAt            time.Time
	Now                   time.Time
}

type AIRecord struct {
	ID                    string
	AccountID             string
	DeviceID              string
	Source                string
	Coverage              string
	CiphertextObjectKey   string
	ContentSHA256         [sha256.Size]byte
	ClientDeduplicationID string
	CaptureID             string
	SegmentIndex          int64
	FinalSegment          bool
	PreviousSegmentSHA256 []byte
	CaptureVersion        int64
	AnalysisState         string
	OccurredAt            time.Time
	IngestedAt            time.Time
	PurgeAfter            time.Time
	HistoryRetainUntil    time.Time
	kmsEnvelope           []byte
	offlineEnvelope       []byte
}

type AIAnalysisLease struct {
	JobID          string
	Record         AIRecord
	KMSEnvelope    []byte
	LeaseOwner     string
	LeaseExpiresAt time.Time
	Attempt        int64
}

type AIFindingInput struct {
	Kind        string
	Severity    string
	SummaryCode string
}

type AIAnalysisResult struct {
	JobID             string
	RecordID          string
	WorkerID          string
	ClassifierVersion string
	RulesVersion      string
	Findings          []AIFindingInput
	Now               time.Time
}

type AIAnalysisCompletion struct {
	RecordID        string
	FindingCount    int
	ActionHoldCount int
	Duplicate       bool
}

type AIAdminProof struct {
	IsMasterAdmin    bool
	WebAuthnVerified bool
	AssertionID      string
	VerifiedAt       time.Time
}

type AIRawReadRequest struct {
	RecordID   string
	AdminActor string
	Reason     string
	Proof      AIAdminProof
	Now        time.Time
}

type AIRawReadGrant struct {
	RecordID            string
	CiphertextObjectKey string
	KMSEnvelope         []byte
	ContentSHA256       [sha256.Size]byte
	ExpiresAt           time.Time
}

type AIActionConfirmation struct {
	HoldID            string
	AccountID         string
	DeviceID          string
	AssertionVerified bool
	AssertionID       string
	VerifiedAt        time.Time
	Now               time.Time
}

func (s *Store) CreateAIRecord(ctx context.Context, input AIRecordInput) (AIRecord, error) {
	input.Now = normalizedTime(input.Now)
	input.OccurredAt = input.OccurredAt.UTC()
	if err := validateAIRecordInput(input); err != nil {
		return AIRecord{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AIRecord{}, err
	}
	defer tx.Rollback()
	if existing, err := aiRecordByDedupeTx(ctx, tx, input.ClientDeduplicationID); err == nil {
		if !sameAIRecordInput(existing, input) {
			return AIRecord{}, ErrVersionConflict
		}
		if err := tx.Commit(); err != nil {
			return AIRecord{}, err
		}
		return existing, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return AIRecord{}, err
	}
	var accountState, deviceState, deviceAccount string
	if err := tx.QueryRowContext(ctx, `SELECT a.state, d.state, d.account_id
		FROM accounts a JOIN devices d ON d.id = ? WHERE a.id = ?`, input.DeviceID, input.AccountID).
		Scan(&accountState, &deviceState, &deviceAccount); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return AIRecord{}, ErrResourceNotFound
		}
		return AIRecord{}, err
	}
	if accountState != "active" || deviceAccount != input.AccountID || deviceState != "active" {
		return AIRecord{}, ErrInvalidState
	}
	if input.SegmentIndex > 0 {
		var previousHash []byte
		var previousFinal int
		var previousAccount, previousSource string
		err := tx.QueryRowContext(ctx, `SELECT content_sha256, final_segment, account_id, source FROM ai_records
			WHERE device_id = ? AND capture_id = ? AND segment_index = ?`, input.DeviceID, input.CaptureID, input.SegmentIndex-1).
			Scan(&previousHash, &previousFinal, &previousAccount, &previousSource)
		if errors.Is(err, sql.ErrNoRows) {
			return AIRecord{}, ErrInvalidState
		}
		if err != nil {
			return AIRecord{}, err
		}
		if previousFinal != 0 || previousAccount != input.AccountID || previousSource != input.Source ||
			!bytes.Equal(previousHash, input.PreviousSegmentSHA256) {
			return AIRecord{}, ErrInvalidState
		}
	}
	recordID, err := idgen.New("air")
	if err != nil {
		return AIRecord{}, err
	}
	jobID, err := idgen.New("job")
	if err != nil {
		return AIRecord{}, err
	}
	stamp := input.Now.Format(time.RFC3339Nano)
	purgeAfter := input.Now.Add(aiRawRetention)
	historyRetainUntil := input.Now.Add(aiHistoryRetention)
	if _, err := tx.ExecContext(ctx, `INSERT INTO ai_records
		(id, account_id, device_id, source, coverage, ciphertext_object_key, kms_envelope,
		offline_envelope, content_sha256, occurred_at, purge_after, client_deduplication_id,
		capture_id, segment_index, final_segment, previous_segment_sha256, capture_version,
		analysis_state, ingested_at, history_retain_until)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'queued', ?, ?)`, recordID,
		input.AccountID, input.DeviceID, input.Source, input.Coverage, input.CiphertextObjectKey,
		input.KMSEnvelope, input.OfflineEnvelope, input.ContentSHA256[:],
		input.OccurredAt.Format(time.RFC3339Nano), purgeAfter.Format(time.RFC3339Nano),
		input.ClientDeduplicationID, input.CaptureID, input.SegmentIndex, boolInt(input.FinalSegment),
		nullablePreviousHash(input.PreviousSegmentSHA256), input.CaptureVersion, stamp,
		historyRetainUntil.Format(time.RFC3339Nano)); err != nil {
		if constraintContains(err, "ai_records.client_deduplication_id") || constraintContains(err, "ai_records.ciphertext_object_key") {
			return AIRecord{}, ErrVersionConflict
		}
		return AIRecord{}, err
	}
	payload, _ := json.Marshal(map[string]string{"record_id": recordID})
	if _, err := tx.ExecContext(ctx, `INSERT INTO durable_jobs
		(id, kind, deduplication_id, payload_json, state, available_at, created_at, updated_at)
		VALUES (?, 'ai.analyze', ?, ?, 'ready', ?, ?, ?)`, jobID, "ai:analyze:"+recordID,
		string(payload), stamp, stamp, stamp); err != nil {
		return AIRecord{}, err
	}
	if _, err := appendAuditTx(ctx, tx, input.AccountID, "ai.record.ingest", recordID, true,
		map[string]any{"source": input.Source, "coverage": input.Coverage, "capture_version": input.CaptureVersion}, input.Now); err != nil {
		return AIRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return AIRecord{}, err
	}
	return AIRecord{ID: recordID, AccountID: input.AccountID, DeviceID: input.DeviceID,
		Source: input.Source, Coverage: input.Coverage, CiphertextObjectKey: input.CiphertextObjectKey,
		ContentSHA256: input.ContentSHA256, ClientDeduplicationID: input.ClientDeduplicationID,
		CaptureID: input.CaptureID, SegmentIndex: input.SegmentIndex, FinalSegment: input.FinalSegment,
		PreviousSegmentSHA256: append([]byte(nil), input.PreviousSegmentSHA256...),
		CaptureVersion:        input.CaptureVersion, AnalysisState: "queued", OccurredAt: input.OccurredAt,
		IngestedAt: input.Now, PurgeAfter: purgeAfter, HistoryRetainUntil: historyRetainUntil}, nil
}

func validateAIRecordInput(input AIRecordInput) error {
	validSource := input.Source == "codex-cli" || input.Source == "claude-code-cli" || input.Source == "safari" ||
		input.Source == "chatgpt-native" || input.Source == "claude-native" || input.Source == "cowork-native"
	validCoverage := input.Coverage == "full" || input.Coverage == "partial" || input.Coverage == "content-unavailable"
	if !opaqueID.MatchString(input.AccountID) || !strings.HasPrefix(input.AccountID, "usr_") ||
		!opaqueID.MatchString(input.DeviceID) || !strings.HasPrefix(input.DeviceID, "dev_") ||
		!validSource || !validCoverage || !aiObjectKey.MatchString(input.CiphertextObjectKey) ||
		!safeDedupeID.MatchString(input.ClientDeduplicationID) || !opaqueID.MatchString(input.CaptureID) ||
		!strings.HasPrefix(input.CaptureID, "cap_") || input.SegmentIndex < 0 || input.CaptureVersion != 1 {
		return errors.New("AI record identity or metadata is invalid")
	}
	if (input.SegmentIndex == 0 && len(input.PreviousSegmentSHA256) != 0) ||
		(input.SegmentIndex > 0 && len(input.PreviousSegmentSHA256) != sha256.Size) {
		return errors.New("AI record segment chain is invalid")
	}
	if len(input.KMSEnvelope) < 1 || len(input.KMSEnvelope) > 6144 ||
		len(input.OfflineEnvelope) < 48 || len(input.OfflineEnvelope) > 4096 {
		return errors.New("AI record key envelopes are invalid")
	}
	if input.OccurredAt.IsZero() || input.OccurredAt.Before(input.Now.Add(-30*24*time.Hour)) ||
		input.OccurredAt.After(input.Now.Add(5*time.Minute)) {
		return errors.New("AI record occurrence time is invalid")
	}
	return nil
}

func sameAIRecordInput(record AIRecord, input AIRecordInput) bool {
	return record.AccountID == input.AccountID && record.DeviceID == input.DeviceID && record.Source == input.Source &&
		record.Coverage == input.Coverage && record.CiphertextObjectKey == input.CiphertextObjectKey &&
		record.ContentSHA256 == input.ContentSHA256 && record.CaptureVersion == input.CaptureVersion &&
		record.OccurredAt.Equal(input.OccurredAt) && bytes.Equal(record.kmsEnvelope, input.KMSEnvelope) &&
		bytes.Equal(record.offlineEnvelope, input.OfflineEnvelope) && record.CaptureID == input.CaptureID &&
		record.SegmentIndex == input.SegmentIndex && record.FinalSegment == input.FinalSegment &&
		bytes.Equal(record.PreviousSegmentSHA256, input.PreviousSegmentSHA256)
}

func (s *Store) LeaseNextAIAnalysis(ctx context.Context, workerID string, leaseDuration time.Duration, now time.Time) (AIAnalysisLease, error) {
	now = normalizedTime(now)
	if !safeWorkerID.MatchString(workerID) || leaseDuration < 5*time.Second || leaseDuration > 10*time.Minute {
		return AIAnalysisLease{}, errors.New("AI analysis lease is invalid")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AIAnalysisLease{}, err
	}
	defer tx.Rollback()
	stamp := now.Format(time.RFC3339Nano)
	var jobID, recordID string
	err = tx.QueryRowContext(ctx, `SELECT j.id, r.id FROM durable_jobs j JOIN ai_records r
		ON j.deduplication_id = 'ai:analyze:' || r.id
		WHERE j.kind = 'ai.analyze' AND r.wraps_destroyed_at IS NULL AND r.purge_after > ?
		AND ((j.state = 'ready' AND j.available_at <= ?) OR (j.state = 'leased' AND j.lease_expires_at <= ?))
		ORDER BY j.available_at, j.created_at, j.id LIMIT 1`, stamp, stamp, stamp).Scan(&jobID, &recordID)
	if errors.Is(err, sql.ErrNoRows) {
		return AIAnalysisLease{}, ErrNoWork
	}
	if err != nil {
		return AIAnalysisLease{}, err
	}
	expires := now.Add(leaseDuration)
	result, err := tx.ExecContext(ctx, `UPDATE durable_jobs SET state = 'leased', lease_owner = ?,
		lease_expires_at = ?, heartbeat_at = ?, attempts = attempts + 1, updated_at = ?
		WHERE id = ? AND ((state = 'ready' AND available_at <= ?) OR (state = 'leased' AND lease_expires_at <= ?))`,
		workerID, expires.Format(time.RFC3339Nano), stamp, stamp, jobID, stamp, stamp)
	if err != nil {
		return AIAnalysisLease{}, err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return AIAnalysisLease{}, ErrNoWork
	}
	if _, err := tx.ExecContext(ctx, `UPDATE ai_records SET analysis_state = 'analyzing'
		WHERE id = ? AND analysis_state IN ('queued', 'analyzing') AND wraps_destroyed_at IS NULL`, recordID); err != nil {
		return AIAnalysisLease{}, err
	}
	lease, err := aiAnalysisLeaseTx(ctx, tx, jobID, recordID)
	if err != nil {
		return AIAnalysisLease{}, err
	}
	lease.LeaseOwner = workerID
	lease.LeaseExpiresAt = expires
	if err := tx.Commit(); err != nil {
		return AIAnalysisLease{}, err
	}
	return lease, nil
}

func (s *Store) CompleteAIAnalysis(ctx context.Context, input AIAnalysisResult) (AIAnalysisCompletion, error) {
	input.Now = normalizedTime(input.Now)
	if !safeWorkerID.MatchString(input.WorkerID) || !opaqueID.MatchString(input.RecordID) ||
		!opaqueID.MatchString(input.JobID) || !aiReleaseToken.MatchString(input.ClassifierVersion) ||
		!aiReleaseToken.MatchString(input.RulesVersion) || len(input.Findings) > 100 {
		return AIAnalysisCompletion{}, errors.New("AI analysis result metadata is invalid")
	}
	for _, finding := range input.Findings {
		if !validAIFinding(finding) {
			return AIAnalysisCompletion{}, errors.New("AI analysis finding is invalid")
		}
	}
	resultHash := hashAIAnalysisResult(input)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AIAnalysisCompletion{}, err
	}
	defer tx.Rollback()
	var jobState, leaseOwner, leaseExpires, dedupeID, recordState, purgeAfter string
	var storedResultHash []byte
	var wrapsDestroyed sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT j.state, COALESCE(j.lease_owner, ''), COALESCE(j.lease_expires_at, ''),
		j.deduplication_id, r.analysis_state, r.purge_after, r.wraps_destroyed_at, r.analysis_result_sha256
		FROM durable_jobs j JOIN ai_records r ON r.id = ? WHERE j.id = ?`, input.RecordID, input.JobID).
		Scan(&jobState, &leaseOwner, &leaseExpires, &dedupeID, &recordState, &purgeAfter, &wrapsDestroyed, &storedResultHash)
	if errors.Is(err, sql.ErrNoRows) {
		return AIAnalysisCompletion{}, ErrResourceNotFound
	}
	if err != nil {
		return AIAnalysisCompletion{}, err
	}
	if dedupeID != "ai:analyze:"+input.RecordID {
		return AIAnalysisCompletion{}, ErrResourceNotFound
	}
	if jobState == "succeeded" && recordState == "complete" {
		if len(storedResultHash) != sha256.Size || !bytes.Equal(storedResultHash, resultHash[:]) {
			return AIAnalysisCompletion{}, ErrVersionConflict
		}
		var findings, holds int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM ai_findings WHERE record_id = ?", input.RecordID).Scan(&findings); err != nil {
			return AIAnalysisCompletion{}, err
		}
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM ai_action_holds WHERE record_id = ?", input.RecordID).Scan(&holds); err != nil {
			return AIAnalysisCompletion{}, err
		}
		if err := tx.Commit(); err != nil {
			return AIAnalysisCompletion{}, err
		}
		return AIAnalysisCompletion{RecordID: input.RecordID, FindingCount: findings, ActionHoldCount: holds, Duplicate: true}, nil
	}
	leaseDeadline, parseErr := time.Parse(time.RFC3339Nano, leaseExpires)
	rawDeadline, rawErr := time.Parse(time.RFC3339Nano, purgeAfter)
	if jobState != "leased" || leaseOwner != input.WorkerID || parseErr != nil || !input.Now.Before(leaseDeadline) ||
		rawErr != nil || !input.Now.Before(rawDeadline) || wrapsDestroyed.Valid || recordState != "analyzing" {
		return AIAnalysisCompletion{}, ErrInvalidState
	}
	var accountID, deviceID string
	if err := tx.QueryRowContext(ctx, "SELECT account_id, device_id FROM ai_records WHERE id = ?", input.RecordID).Scan(&accountID, &deviceID); err != nil {
		return AIAnalysisCompletion{}, err
	}
	stamp := input.Now.Format(time.RFC3339Nano)
	retainUntil := input.Now.Add(aiHistoryRetention).Format(time.RFC3339Nano)
	holds := 0
	for _, finding := range input.Findings {
		findingID, err := idgen.New("aif")
		if err != nil {
			return AIAnalysisCompletion{}, err
		}
		findingHash := hashAIFinding(input.RecordID, input.ClassifierVersion, input.RulesVersion, finding)
		if _, err := tx.ExecContext(ctx, `INSERT INTO ai_findings
			(id, record_id, kind, severity, classifier_version, rules_version, finding_hash, summary, created_at, retain_until)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, findingID, input.RecordID, finding.Kind, finding.Severity,
			input.ClassifierVersion, input.RulesVersion, findingHash[:], finding.SummaryCode, stamp, retainUntil); err != nil {
			return AIAnalysisCompletion{}, err
		}
		if finding.Kind == "prompt-injection" {
			holdID, err := idgen.New("hold")
			if err != nil {
				return AIAnalysisCompletion{}, err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO ai_action_holds
				(id, account_id, device_id, record_id, finding_id, state, created_at)
				VALUES (?, ?, ?, ?, ?, 'pending', ?)`, holdID, accountID, deviceID, input.RecordID, findingID, stamp); err != nil {
				return AIAnalysisCompletion{}, err
			}
			holds++
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE ai_records SET analysis_state = 'complete', analyzed_at = ?,
		analysis_result_sha256 = ? WHERE id = ? AND analysis_state = 'analyzing'`, stamp, resultHash[:], input.RecordID); err != nil {
		return AIAnalysisCompletion{}, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE durable_jobs SET state = 'succeeded', lease_owner = NULL,
		lease_expires_at = NULL, heartbeat_at = NULL, last_error = NULL, updated_at = ?
		WHERE id = ? AND state = 'leased' AND lease_owner = ? AND lease_expires_at > ?`,
		stamp, input.JobID, input.WorkerID, stamp)
	if err != nil {
		return AIAnalysisCompletion{}, err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return AIAnalysisCompletion{}, ErrVersionConflict
	}
	if _, err := appendAuditTx(ctx, tx, "ai-analyzer:"+input.WorkerID, "ai.analysis.complete", input.RecordID, true,
		map[string]any{"findings": len(input.Findings), "action_holds": holds,
			"classifier_version": input.ClassifierVersion, "rules_version": input.RulesVersion}, input.Now); err != nil {
		return AIAnalysisCompletion{}, err
	}
	if err := tx.Commit(); err != nil {
		return AIAnalysisCompletion{}, err
	}
	return AIAnalysisCompletion{RecordID: input.RecordID, FindingCount: len(input.Findings), ActionHoldCount: holds}, nil
}

func (s *Store) RetryAIAnalysis(ctx context.Context, jobID, recordID, workerID, failure string, availableAt, now time.Time) error {
	now = normalizedTime(now)
	failure = sanitizeJobError(failure)
	if !safeWorkerID.MatchString(workerID) || failure == "" || availableAt.IsZero() || !availableAt.After(now) {
		return errors.New("AI analysis retry is invalid")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stamp := now.Format(time.RFC3339Nano)
	result, err := tx.ExecContext(ctx, `UPDATE durable_jobs SET state = 'ready', available_at = ?,
		lease_owner = NULL, lease_expires_at = NULL, heartbeat_at = NULL, last_error = ?, updated_at = ?
		WHERE id = ? AND deduplication_id = ? AND state = 'leased' AND lease_owner = ? AND lease_expires_at > ?`,
		availableAt.UTC().Format(time.RFC3339Nano), failure, stamp, jobID, "ai:analyze:"+recordID, workerID, stamp)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return ErrResourceNotFound
	}
	recordResult, err := tx.ExecContext(ctx, `UPDATE ai_records SET analysis_state = 'queued'
		WHERE id = ? AND analysis_state = 'analyzing' AND wraps_destroyed_at IS NULL AND purge_after > ?`, recordID, stamp)
	if err != nil {
		return err
	}
	if changed, _ := recordResult.RowsAffected(); changed != 1 {
		return ErrInvalidState
	}
	return tx.Commit()
}

func (s *Store) AuthorizeAIRawRead(ctx context.Context, request AIRawReadRequest) (AIRawReadGrant, error) {
	request.Now = normalizedTime(request.Now)
	request.Reason = sanitizeJobError(request.Reason)
	if !request.Proof.IsMasterAdmin || !request.Proof.WebAuthnVerified || strings.TrimSpace(request.AdminActor) == "" ||
		len(request.Reason) < 8 || len(request.Reason) > 500 || !aiReleaseToken.MatchString(request.Proof.AssertionID) ||
		request.Proof.VerifiedAt.IsZero() || request.Proof.VerifiedAt.After(request.Now.Add(time.Minute)) ||
		request.Now.Sub(request.Proof.VerifiedAt) > 10*time.Minute {
		return AIRawReadGrant{}, ErrAIRawUnavailable
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AIRawReadGrant{}, err
	}
	defer tx.Rollback()
	var grant AIRawReadGrant
	var contentHash []byte
	var purgeAfter string
	err = tx.QueryRowContext(ctx, `SELECT id, ciphertext_object_key, kms_envelope, content_sha256, purge_after
		FROM ai_records WHERE id = ? AND wraps_destroyed_at IS NULL`, request.RecordID).
		Scan(&grant.RecordID, &grant.CiphertextObjectKey, &grant.KMSEnvelope, &contentHash, &purgeAfter)
	if errors.Is(err, sql.ErrNoRows) {
		return AIRawReadGrant{}, ErrAIRawUnavailable
	}
	if err != nil {
		return AIRawReadGrant{}, err
	}
	grant.ExpiresAt, err = time.Parse(time.RFC3339Nano, purgeAfter)
	if err != nil || !request.Now.Before(grant.ExpiresAt) || len(contentHash) != sha256.Size {
		return AIRawReadGrant{}, ErrAIRawUnavailable
	}
	copy(grant.ContentSHA256[:], contentHash)
	if _, err := appendAuditTx(ctx, tx, request.AdminActor, "ai.raw.authorize", request.RecordID, true,
		map[string]any{"reason": request.Reason, "fresh_webauthn": true}, request.Now); err != nil {
		return AIRawReadGrant{}, err
	}
	if err := tx.Commit(); err != nil {
		return AIRawReadGrant{}, err
	}
	return grant, nil
}

func (s *Store) RequireAIActionClear(ctx context.Context, accountID, deviceID string) error {
	var pending int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM ai_action_holds
		WHERE account_id = ? AND device_id = ? AND state = 'pending'`, accountID, deviceID).Scan(&pending); err != nil {
		return err
	}
	if pending > 0 {
		return ErrAIConfirmationRequired
	}
	return nil
}

func (s *Store) ConfirmAIActionHold(ctx context.Context, input AIActionConfirmation) error {
	input.Now = normalizedTime(input.Now)
	if !input.AssertionVerified || !opaqueID.MatchString(input.HoldID) || !strings.HasPrefix(input.HoldID, "hold_") ||
		!aiReleaseToken.MatchString(input.AssertionID) || input.VerifiedAt.IsZero() ||
		input.VerifiedAt.After(input.Now.Add(time.Minute)) || input.Now.Sub(input.VerifiedAt) > 10*time.Minute {
		return ErrAIConfirmationRequired
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stamp := input.Now.Format(time.RFC3339Nano)
	result, err := tx.ExecContext(ctx, `UPDATE ai_action_holds SET state = 'confirmed', confirmed_at = ?, confirmed_by = ?
		WHERE id = ? AND account_id = ? AND device_id = ? AND state = 'pending'`, stamp, input.AccountID,
		input.HoldID, input.AccountID, input.DeviceID)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return ErrAIConfirmationRequired
	}
	if _, err := appendAuditTx(ctx, tx, input.AccountID, "ai.action-hold.confirm", input.DeviceID, true,
		map[string]any{"hold_id": input.HoldID, "fresh_passkey": true}, input.Now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) PurgeExpiredAIRaw(ctx context.Context, now time.Time) (int64, error) {
	now = normalizedTime(now)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	stamp := now.Format(time.RFC3339Nano)
	rows, err := tx.QueryContext(ctx, `SELECT id, ciphertext_object_key FROM ai_records
		WHERE wraps_destroyed_at IS NULL AND purge_after <= ? ORDER BY id`, stamp)
	if err != nil {
		return 0, err
	}
	type expiredRecord struct{ id, objectKey string }
	var records []expiredRecord
	for rows.Next() {
		var record expiredRecord
		if err := rows.Scan(&record.id, &record.objectKey); err != nil {
			rows.Close()
			return 0, err
		}
		records = append(records, record)
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for _, record := range records {
		payload, _ := json.Marshal(map[string]string{"record_id": record.id, "object_key": record.objectKey, "destroyed_at": stamp})
		if _, err := enqueueOutboxTx(ctx, tx, "ai.delete", "ai:delete:"+record.id, payload, now); err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE durable_jobs SET state = 'cancelled', lease_owner = NULL,
			lease_expires_at = NULL, heartbeat_at = NULL, updated_at = ? WHERE deduplication_id = ?
			AND state IN ('ready', 'leased')`, stamp, "ai:analyze:"+record.id); err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE ai_records SET kms_envelope = zeroblob(length(kms_envelope)),
			offline_envelope = zeroblob(length(offline_envelope)), wraps_destroyed_at = ?, purge_queued_at = ?,
			analysis_state = 'purged' WHERE id = ? AND wraps_destroyed_at IS NULL`, stamp, stamp, record.id); err != nil {
			return 0, err
		}
		if _, err := appendAuditTx(ctx, tx, "system", "ai.raw.crypto-purge", record.id, true,
			map[string]any{"ciphertext_delete_queued": true}, now); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return int64(len(records)), nil
}

func (s *Store) PurgeExpiredAIHistory(ctx context.Context, now time.Time) (int64, error) {
	now = normalizedTime(now)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	stamp := now.Format(time.RFC3339Nano)
	rows, err := tx.QueryContext(ctx, `SELECT id FROM ai_records WHERE wraps_destroyed_at IS NOT NULL
		AND history_retain_until IS NOT NULL AND history_retain_until <= ? ORDER BY id`, stamp)
	if err != nil {
		return 0, err
	}
	var recordIDs []string
	for rows.Next() {
		var recordID string
		if err := rows.Scan(&recordID); err != nil {
			rows.Close()
			return 0, err
		}
		recordIDs = append(recordIDs, recordID)
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for _, recordID := range recordIDs {
		if _, err := tx.ExecContext(ctx, "DELETE FROM ai_action_holds WHERE record_id = ?", recordID); err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM ai_findings WHERE record_id = ?", recordID); err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM durable_jobs WHERE deduplication_id = ?", "ai:analyze:"+recordID); err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM ai_records WHERE id = ?", recordID); err != nil {
			return 0, err
		}
	}
	if len(recordIDs) > 0 {
		if _, err := appendAuditTx(ctx, tx, "system", "ai.history.purge", "ai-history", true,
			map[string]any{"records_purged": len(recordIDs)}, now); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return int64(len(recordIDs)), nil
}

func validAIFinding(finding AIFindingInput) bool {
	validSeverity := finding.Severity == "info" || finding.Severity == "low" || finding.Severity == "medium" ||
		finding.Severity == "high" || finding.Severity == "critical"
	return aiFindingCode.MatchString(finding.Kind) && validSeverity && aiFindingCode.MatchString(finding.SummaryCode)
}

func hashAIFinding(recordID, classifierVersion, rulesVersion string, finding AIFindingInput) [sha256.Size]byte {
	encoded, _ := json.Marshal([]string{recordID, classifierVersion, rulesVersion, finding.Kind, finding.Severity, finding.SummaryCode})
	return sha256.Sum256(append([]byte("plntir-ai-finding-v1\x00"), encoded...))
}

func hashAIAnalysisResult(input AIAnalysisResult) [sha256.Size]byte {
	encoded, _ := json.Marshal(struct {
		RecordID          string           `json:"record_id"`
		ClassifierVersion string           `json:"classifier_version"`
		RulesVersion      string           `json:"rules_version"`
		Findings          []AIFindingInput `json:"findings"`
	}{input.RecordID, input.ClassifierVersion, input.RulesVersion, input.Findings})
	return sha256.Sum256(append([]byte("plntir-ai-analysis-v1\x00"), encoded...))
}

func aiRecordByDedupeTx(ctx context.Context, tx *sql.Tx, dedupeID string) (AIRecord, error) {
	var record AIRecord
	var hash []byte
	var occurredAt, ingestedAt, purgeAfter, retainUntil string
	var finalSegment int
	err := tx.QueryRowContext(ctx, `SELECT id, account_id, device_id, source, coverage, ciphertext_object_key,
		content_sha256, kms_envelope, offline_envelope, client_deduplication_id, capture_id, segment_index,
		final_segment, previous_segment_sha256, capture_version, analysis_state, occurred_at,
		COALESCE(ingested_at, occurred_at), purge_after, COALESCE(history_retain_until, purge_after)
		FROM ai_records WHERE client_deduplication_id = ?`, dedupeID).
		Scan(&record.ID, &record.AccountID, &record.DeviceID, &record.Source, &record.Coverage,
			&record.CiphertextObjectKey, &hash, &record.kmsEnvelope, &record.offlineEnvelope,
			&record.ClientDeduplicationID, &record.CaptureID, &record.SegmentIndex, &finalSegment,
			&record.PreviousSegmentSHA256, &record.CaptureVersion,
			&record.AnalysisState, &occurredAt, &ingestedAt, &purgeAfter, &retainUntil)
	if err != nil {
		return AIRecord{}, err
	}
	if len(hash) != sha256.Size {
		return AIRecord{}, errors.New("AI record hash is invalid")
	}
	copy(record.ContentSHA256[:], hash)
	record.FinalSegment = finalSegment == 1
	for target, encoded := range map[*time.Time]string{&record.OccurredAt: occurredAt, &record.IngestedAt: ingestedAt,
		&record.PurgeAfter: purgeAfter, &record.HistoryRetainUntil: retainUntil} {
		parsed, err := time.Parse(time.RFC3339Nano, encoded)
		if err != nil {
			return AIRecord{}, err
		}
		*target = parsed
	}
	return record, nil
}

func aiAnalysisLeaseTx(ctx context.Context, tx *sql.Tx, jobID, recordID string) (AIAnalysisLease, error) {
	var lease AIAnalysisLease
	var recordHash []byte
	var occurredAt, ingestedAt, purgeAfter, retainUntil, leaseExpires string
	var finalSegment int
	err := tx.QueryRowContext(ctx, `SELECT j.id, j.attempts, COALESCE(j.lease_owner, ''), COALESCE(j.lease_expires_at, ''),
		r.id, r.account_id, r.device_id, r.source, r.coverage, r.ciphertext_object_key, r.kms_envelope,
		r.content_sha256, r.client_deduplication_id, r.capture_id, r.segment_index, r.final_segment,
		r.previous_segment_sha256, r.capture_version, r.analysis_state, r.occurred_at,
		COALESCE(r.ingested_at, r.occurred_at), r.purge_after, COALESCE(r.history_retain_until, r.purge_after)
		FROM durable_jobs j JOIN ai_records r ON r.id = ? WHERE j.id = ?`, recordID, jobID).
		Scan(&lease.JobID, &lease.Attempt, &lease.LeaseOwner, &leaseExpires, &lease.Record.ID,
			&lease.Record.AccountID, &lease.Record.DeviceID, &lease.Record.Source, &lease.Record.Coverage,
			&lease.Record.CiphertextObjectKey, &lease.KMSEnvelope, &recordHash,
			&lease.Record.ClientDeduplicationID, &lease.Record.CaptureID, &lease.Record.SegmentIndex,
			&finalSegment, &lease.Record.PreviousSegmentSHA256, &lease.Record.CaptureVersion,
			&lease.Record.AnalysisState,
			&occurredAt, &ingestedAt, &purgeAfter, &retainUntil)
	if err != nil {
		return AIAnalysisLease{}, err
	}
	if len(recordHash) != sha256.Size {
		return AIAnalysisLease{}, errors.New("AI record hash is invalid")
	}
	copy(lease.Record.ContentSHA256[:], recordHash)
	lease.Record.FinalSegment = finalSegment == 1
	for target, encoded := range map[*time.Time]string{&lease.Record.OccurredAt: occurredAt,
		&lease.Record.IngestedAt: ingestedAt, &lease.Record.PurgeAfter: purgeAfter,
		&lease.Record.HistoryRetainUntil: retainUntil, &lease.LeaseExpiresAt: leaseExpires} {
		parsed, err := time.Parse(time.RFC3339Nano, encoded)
		if err != nil {
			return AIAnalysisLease{}, err
		}
		*target = parsed
	}
	return lease, nil
}

func (record AIRecord) String() string {
	return fmt.Sprintf("AIRecord[%s,%s]", record.ID, record.AnalysisState)
}

func nullablePreviousHash(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return value
}
