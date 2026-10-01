package archive

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"
)

var ErrPolicyPaused = errors.New("archive upload paused by local policy")

type PolicyProbe interface {
	Snapshot(context.Context) (PolicySnapshot, error)
}

type UploadGrantRequest struct {
	DeviceID       string `json:"device_id"`
	ArchiveID      string `json:"archive_id"`
	WorkID         string `json:"work_id"`
	ObjectID       string `json:"object_id"`
	Method         string `json:"method"`
	ContentLength  int64  `json:"content_length"`
	ContentSHA256  string `json:"content_sha256"`
	ChecksumSHA256 string `json:"checksum_sha256"`
}

type UploadGrant struct {
	ObjectID        string            `json:"object_id"`
	Method          string            `json:"method"`
	URL             string            `json:"url"`
	ExpiresAt       time.Time         `json:"expires_at"`
	RequiredHeaders map[string]string `json:"required_headers"`
}

type UploadGrantClient interface {
	Grant(context.Context, UploadGrantRequest) (UploadGrant, error)
}

type PutRequest struct {
	URL            string
	Headers        map[string]string
	Body           []byte
	ContentSHA256  string
	ChecksumSHA256 string
}

type ObjectUploader interface {
	Put(context.Context, PutRequest) error
}

type Runner struct {
	Plan                  Plan
	Store                 StateStore
	Wrapper               KMSWrapper
	Probe                 PolicyProbe
	Grants                UploadGrantClient
	Objects               ObjectUploader
	Now                   func() time.Time
	Random                io.Reader
	AllowLoopbackHTTPTest bool
}

type StepResult struct {
	Complete bool   `json:"complete"`
	Resumed  bool   `json:"resumed"`
	WorkID   string `json:"work_id,omitempty"`
	ObjectID string `json:"object_id,omitempty"`
}

func (runner Runner) Step(ctx context.Context) (StepResult, error) {
	if runner.Wrapper == nil || runner.Probe == nil || runner.Grants == nil || runner.Objects == nil {
		return StepResult{}, errors.New("archive runner dependencies are incomplete")
	}
	if err := runner.Plan.Validate(); err != nil {
		return StepResult{}, err
	}
	now := time.Now().UTC()
	if runner.Now != nil {
		now = runner.Now().UTC()
	}
	snapshot, err := runner.Probe.Snapshot(ctx)
	if err != nil {
		return StepResult{}, fmt.Errorf("local archive policy probe failed closed: %w", err)
	}
	decision, err := EvaluatePolicy(snapshot, now)
	if err != nil {
		return StepResult{}, err
	}
	if !decision.Allowed {
		return StepResult{}, fmt.Errorf("%w: %s", ErrPolicyPaused, decision.Reason)
	}
	state, err := runner.Store.Load()
	if err != nil {
		return StepResult{}, err
	}
	if state.PlanDigestSHA256 != runner.Plan.DigestSHA256 || state.Root != runner.Plan.Root {
		return StepResult{}, errors.New("archive state does not belong to the supplied plan")
	}
	if _, reusedKey := runner.Plan.PriorKeyEnvelopes[state.ArchiveKeyID]; reusedKey {
		return StepResult{}, errors.New("archive state reuses a prior snapshot DEK")
	}
	workByID := make(map[string]WorkChunk, len(runner.Plan.Work))
	for _, work := range runner.Plan.Work {
		workByID[work.ID] = work
	}
	for workID, object := range state.Confirmed {
		planned, exists := workByID[workID]
		if !exists || object.Offset != planned.Offset || object.PlaintextBytes != planned.Length {
			return StepResult{}, errors.New("confirmed archive state does not match the supplied plan")
		}
	}
	resumed := state.Pending != nil
	var work WorkChunk
	if resumed {
		var exists bool
		work, exists = workByID[state.Pending.WorkID]
		if !exists {
			return StepResult{}, errors.New("pending archive work is absent from plan")
		}
	} else {
		found := false
		for _, candidate := range runner.Plan.Work {
			if _, confirmed := state.Confirmed[candidate.ID]; !confirmed {
				work = candidate
				found = true
				break
			}
		}
		if !found {
			return StepResult{Complete: true}, nil
		}
	}
	key, err := UnwrapArchiveDEK(ctx, runner.Wrapper, WrapContext{DeviceID: state.DeviceID, ArchiveKeyID: state.ArchiveKeyID}, state.Envelopes)
	if err != nil {
		return StepResult{}, err
	}
	defer Zero(key)
	prefix, _ := state.NoncePrefix()
	plaintext, err := ReadWorkPlaintext(runner.Plan.Root, work)
	if err != nil {
		return StepResult{}, err
	}
	defer Zero(plaintext)
	var pending PendingUpload
	if resumed {
		pending = *state.Pending
	} else {
		if state.NextNonceCounter == ^uint64(0) {
			return StepResult{}, errors.New("archive nonce counter is exhausted")
		}
		objectID, err := randomObjectID(runner.Random)
		if err != nil {
			return StepResult{}, err
		}
		pending = PendingUpload{
			WorkID:       work.ID,
			ObjectID:     objectID,
			NonceCounter: state.NextNonceCounter,
			ReservedAt:   now,
		}
	}
	aad := ChunkAAD{DeviceID: state.DeviceID, ArchiveID: state.ArchiveID, WorkID: work.ID, ObjectID: pending.ObjectID}
	chunk, err := SealChunk(key, prefix, pending.NonceCounter, aad, plaintext)
	if err != nil {
		return StepResult{}, err
	}
	record, err := EncodeCipherChunk(chunk)
	if err != nil {
		return StepResult{}, err
	}
	payloadDigest := sha256.Sum256(record)
	payloadHex := hex.EncodeToString(payloadDigest[:])
	plaintextHex := hex.EncodeToString(chunk.PlaintextSHA256[:])
	ciphertextHex := hex.EncodeToString(chunk.CiphertextSHA256[:])
	if resumed {
		if pending.PayloadBytes != int64(len(record)) || pending.PayloadSHA256 != payloadHex || pending.PlaintextSHA256 != plaintextHex || pending.CiphertextSHA256 != ciphertextHex {
			return StepResult{}, errors.New("reconstructed pending archive object differs from its durable reservation")
		}
	} else {
		pending.PayloadBytes = int64(len(record))
		pending.PayloadSHA256 = payloadHex
		pending.PlaintextSHA256 = plaintextHex
		pending.CiphertextSHA256 = ciphertextHex
		state.Pending = &pending
		state.NextNonceCounter++
		state.UpdatedAt = now
		if err := runner.Store.Save(state); err != nil {
			return StepResult{}, fmt.Errorf("persist nonce reservation before upload: %w", err)
		}
	}
	checksum := base64.StdEncoding.EncodeToString(payloadDigest[:])
	grantRequest := UploadGrantRequest{
		DeviceID:       state.DeviceID,
		ArchiveID:      state.ArchiveID,
		WorkID:         work.ID,
		ObjectID:       pending.ObjectID,
		Method:         "PUT",
		ContentLength:  int64(len(record)),
		ContentSHA256:  payloadHex,
		ChecksumSHA256: checksum,
	}
	grant, err := runner.Grants.Grant(ctx, grantRequest)
	if err != nil {
		return StepResult{}, err
	}
	if err := validateGrant(grant, grantRequest, now, runner.AllowLoopbackHTTPTest); err != nil {
		return StepResult{}, err
	}
	if err := runner.Objects.Put(ctx, PutRequest{URL: grant.URL, Headers: grant.RequiredHeaders, Body: record, ContentSHA256: payloadHex, ChecksumSHA256: checksum}); err != nil {
		return StepResult{}, err
	}
	if state.Confirmed == nil {
		state.Confirmed = make(map[string]ObjectRef)
	}
	state.Confirmed[work.ID] = ObjectRef{
		ObjectID:        pending.ObjectID,
		DeviceID:        state.DeviceID,
		ArchiveID:       state.ArchiveID,
		ArchiveKeyID:    state.ArchiveKeyID,
		WorkID:          work.ID,
		Offset:          work.Offset,
		PlaintextBytes:  work.Length,
		CiphertextBytes: int64(len(record)),
		NonceCounter:    pending.NonceCounter,
		CiphertextHash:  payloadHex,
	}
	state.Pending = nil
	state.UpdatedAt = now
	if err := runner.Store.Save(state); err != nil {
		return StepResult{}, fmt.Errorf("persist confirmed archive object: %w", err)
	}
	return StepResult{
		Complete: len(state.Confirmed) == len(runner.Plan.Work),
		Resumed:  resumed,
		WorkID:   work.ID,
		ObjectID: pending.ObjectID,
	}, nil
}

func randomObjectID(source io.Reader) (string, error) {
	if source == nil {
		source = rand.Reader
	}
	value := make([]byte, 32)
	if _, err := io.ReadFull(source, value); err != nil {
		return "", fmt.Errorf("generate opaque archive object ID: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}
