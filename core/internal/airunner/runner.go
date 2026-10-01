package airunner

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"time"

	"plntir/core/internal/aianalyzer"
	"plntir/core/internal/aitelemetry"
	"plntir/core/internal/filecrypto"
	storesqlite "plntir/core/internal/store/sqlite"
)

const leaseDuration = 5 * time.Minute

type Store interface {
	LeaseNextAIAnalysis(context.Context, string, time.Duration, time.Time) (storesqlite.AIAnalysisLease, error)
	CompleteAIAnalysis(context.Context, storesqlite.AIAnalysisResult) (storesqlite.AIAnalysisCompletion, error)
	RetryAIAnalysis(context.Context, string, string, string, string, time.Time, time.Time) error
}

type ObjectReader interface {
	ReadCiphertext(context.Context, string, int64) ([]byte, error)
}

type KeyContext struct {
	Purpose   string
	RecordID  string
	AccountID string
	DeviceID  string
	ObjectKey string
}

type KeyUnwrapper interface {
	Unwrap(context.Context, []byte, KeyContext) ([]byte, error)
}

type Runner struct {
	store    Store
	objects  ObjectReader
	keys     KeyUnwrapper
	analyzer *aianalyzer.Analyzer
	now      func() time.Time
}

type Outcome struct {
	State        string
	RecordID     string
	FindingCount int
}

func New(store Store, objects ObjectReader, keys KeyUnwrapper, analyzer *aianalyzer.Analyzer) (*Runner, error) {
	if store == nil || objects == nil || keys == nil || analyzer == nil {
		return nil, errors.New("AI runner dependencies are required")
	}
	return &Runner{store: store, objects: objects, keys: keys, analyzer: analyzer, now: time.Now}, nil
}

func (runner *Runner) ProcessOnce(ctx context.Context, workerID string) (Outcome, error) {
	lease, err := runner.store.LeaseNextAIAnalysis(ctx, workerID, leaseDuration, runner.now().UTC())
	if err != nil {
		return Outcome{}, err
	}
	fail := func(code string) (Outcome, error) {
		now := runner.now().UTC()
		backoff := retryBackoff(lease.Attempt)
		if retryErr := runner.store.RetryAIAnalysis(ctx, lease.JobID, lease.Record.ID, workerID, code, now.Add(backoff), now); retryErr != nil {
			return Outcome{}, errors.New("ai-analysis-retry-state-failed")
		}
		return Outcome{State: "retry_scheduled", RecordID: lease.Record.ID}, errors.New(code)
	}
	ciphertext, err := runner.objects.ReadCiphertext(ctx, lease.Record.CiphertextObjectKey, aitelemetry.MaximumSegmentBytes+4096)
	if err != nil || len(ciphertext) == 0 || len(ciphertext) > aitelemetry.MaximumSegmentBytes+4096 {
		return fail("ai-object-read-failed")
	}
	defer zero(ciphertext)
	key, err := runner.keys.Unwrap(ctx, lease.KMSEnvelope, KeyContext{Purpose: "ai-analysis",
		RecordID: lease.Record.ID, AccountID: lease.Record.AccountID, DeviceID: lease.Record.DeviceID,
		ObjectKey: lease.Record.CiphertextObjectKey})
	if err != nil || len(key) != filecrypto.KeyBytes {
		zero(key)
		return fail("ai-key-unwrap-failed")
	}
	defer zero(key)
	record, err := aitelemetry.Open(ciphertext, aitelemetry.Binding{AccountID: lease.Record.AccountID,
		DeviceID: lease.Record.DeviceID, CaptureID: lease.Record.CaptureID}, key)
	if err != nil {
		return fail("ai-record-authentication-failed")
	}
	encoded, err := aitelemetry.Marshal(record)
	if err != nil {
		return fail("ai-record-schema-failed")
	}
	digest := sha256.Sum256(encoded)
	if subtle.ConstantTimeCompare(digest[:], lease.Record.ContentSHA256[:]) != 1 ||
		record.Source != lease.Record.Source || record.Coverage != lease.Record.Coverage ||
		int64(record.SegmentIndex) != lease.Record.SegmentIndex || record.FinalSegment != lease.Record.FinalSegment ||
		record.PreviousSegmentSHA256 != encodedPreviousHash(lease.Record.PreviousSegmentSHA256) {
		return fail("ai-record-metadata-mismatch")
	}
	analysis, err := runner.analyzer.Analyze(record)
	if err != nil {
		return fail("ai-classifier-failed")
	}
	findings := make([]storesqlite.AIFindingInput, 0, len(analysis.Findings))
	for _, finding := range analysis.Findings {
		findings = append(findings, storesqlite.AIFindingInput{Kind: finding.Kind, Severity: finding.Severity,
			SummaryCode: finding.SummaryCode})
	}
	completion, err := runner.store.CompleteAIAnalysis(ctx, storesqlite.AIAnalysisResult{JobID: lease.JobID,
		RecordID: lease.Record.ID, WorkerID: workerID, ClassifierVersion: analysis.ClassifierVersion,
		RulesVersion: analysis.RulesVersion, Findings: findings, Now: runner.now().UTC()})
	if err != nil {
		return fail("ai-result-commit-failed")
	}
	return Outcome{State: "processed", RecordID: lease.Record.ID, FindingCount: completion.FindingCount}, nil
}

func retryBackoff(attempt int64) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > 8 {
		attempt = 8
	}
	backoff := time.Duration(1<<attempt) * 5 * time.Second
	if backoff > 30*time.Minute {
		return 30 * time.Minute
	}
	return backoff
}

func encodedPreviousHash(value []byte) string {
	if len(value) == 0 {
		return ""
	}
	return hex.EncodeToString(value)
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
