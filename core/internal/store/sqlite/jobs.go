package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"plntir/core/internal/idgen"
)

const maxJobPayloadBytes = 1 << 20

var (
	ErrNoWork    = errors.New("no work is currently available")
	safeWorkerID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$`)
	safeJobKind  = regexp.MustCompile(`^[a-z][a-z0-9.-]{0,63}$`)
	safeTopic    = regexp.MustCompile(`^[a-z][a-z0-9.-]{0,127}$`)
	safeDedupeID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:~/-]{7,255}$`)
)

type DurableJob struct {
	ID              string
	Kind            string
	DeduplicationID string
	Payload         json.RawMessage
	State           string
	AvailableAt     time.Time
	LeaseOwner      string
	LeaseExpiresAt  *time.Time
	HeartbeatAt     *time.Time
	Attempts        int64
	LastError       string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type OutboxMessage struct {
	ID              string
	Topic           string
	DeduplicationID string
	Payload         json.RawMessage
	CreatedAt       time.Time
	Attempts        int64
}

func (s *Store) EnqueueDurableJob(ctx context.Context, kind, deduplicationID string, payload json.RawMessage, availableAt, now time.Time) (DurableJob, error) {
	now = normalizedTime(now)
	if availableAt.IsZero() {
		availableAt = now
	}
	availableAt = availableAt.UTC()
	if !safeJobKind.MatchString(kind) || !safeDedupeID.MatchString(deduplicationID) {
		return DurableJob{}, errors.New("durable job kind or deduplication id is invalid")
	}
	canonical, err := canonicalJSONObject(payload)
	if err != nil {
		return DurableJob{}, err
	}
	jobID, err := idgen.New("job")
	if err != nil {
		return DurableJob{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return DurableJob{}, err
	}
	defer tx.Rollback()
	if existing, err := durableJobByDedupeTx(ctx, tx, deduplicationID); err == nil {
		if existing.Kind != kind || string(existing.Payload) != string(canonical) {
			return DurableJob{}, ErrVersionConflict
		}
		if err := tx.Commit(); err != nil {
			return DurableJob{}, err
		}
		return existing, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return DurableJob{}, err
	}
	stamp := now.Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `INSERT INTO durable_jobs
		(id, kind, deduplication_id, payload_json, state, available_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, 'ready', ?, ?, ?)`, jobID, kind, deduplicationID, string(canonical),
		availableAt.Format(time.RFC3339Nano), stamp, stamp); err != nil {
		if constraintContains(err, "durable_jobs.deduplication_id") {
			return DurableJob{}, ErrVersionConflict
		}
		return DurableJob{}, err
	}
	job := DurableJob{ID: jobID, Kind: kind, DeduplicationID: deduplicationID, Payload: canonical,
		State: "ready", AvailableAt: availableAt, CreatedAt: now, UpdatedAt: now}
	if err := tx.Commit(); err != nil {
		return DurableJob{}, err
	}
	return job, nil
}

func (s *Store) LeaseNextDurableJob(ctx context.Context, workerID string, leaseDuration time.Duration, now time.Time) (DurableJob, error) {
	now = normalizedTime(now)
	if !safeWorkerID.MatchString(workerID) || leaseDuration < 5*time.Second || leaseDuration > 10*time.Minute {
		return DurableJob{}, errors.New("worker id or lease duration is invalid")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return DurableJob{}, err
	}
	defer tx.Rollback()
	stamp := now.Format(time.RFC3339Nano)
	var jobID string
	err = tx.QueryRowContext(ctx, `SELECT id FROM durable_jobs
		WHERE (state = 'ready' AND available_at <= ?)
		   OR (state = 'leased' AND lease_expires_at <= ?)
		ORDER BY available_at, created_at, id LIMIT 1`, stamp, stamp).Scan(&jobID)
	if errors.Is(err, sql.ErrNoRows) {
		return DurableJob{}, ErrNoWork
	}
	if err != nil {
		return DurableJob{}, err
	}
	expires := now.Add(leaseDuration)
	result, err := tx.ExecContext(ctx, `UPDATE durable_jobs SET state = 'leased', lease_owner = ?,
		lease_expires_at = ?, heartbeat_at = ?, attempts = attempts + 1, updated_at = ?
		WHERE id = ? AND ((state = 'ready' AND available_at <= ?) OR (state = 'leased' AND lease_expires_at <= ?))`,
		workerID, expires.Format(time.RFC3339Nano), stamp, stamp, jobID, stamp, stamp)
	if err != nil {
		return DurableJob{}, err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return DurableJob{}, ErrNoWork
	}
	job, err := durableJobByIDTx(ctx, tx, jobID)
	if err != nil {
		return DurableJob{}, err
	}
	if err := tx.Commit(); err != nil {
		return DurableJob{}, err
	}
	return job, nil
}

func (s *Store) HeartbeatDurableJob(ctx context.Context, jobID, workerID string, leaseDuration time.Duration, now time.Time) (time.Time, error) {
	now = normalizedTime(now)
	if !safeWorkerID.MatchString(workerID) || leaseDuration < 5*time.Second || leaseDuration > 10*time.Minute {
		return time.Time{}, errors.New("worker id or lease duration is invalid")
	}
	expires := now.Add(leaseDuration)
	stamp := now.Format(time.RFC3339Nano)
	result, err := s.db.ExecContext(ctx, `UPDATE durable_jobs SET heartbeat_at = ?, lease_expires_at = ?, updated_at = ?
		WHERE id = ? AND state = 'leased' AND lease_owner = ? AND lease_expires_at > ?`,
		stamp, expires.Format(time.RFC3339Nano), stamp, jobID, workerID, stamp)
	if err != nil {
		return time.Time{}, err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return time.Time{}, ErrResourceNotFound
	}
	return expires, nil
}

func (s *Store) SucceedDurableJob(ctx context.Context, jobID, workerID string, now time.Time) error {
	return s.finishDurableJob(ctx, jobID, workerID, "succeeded", "", time.Time{}, now)
}

func (s *Store) FailDurableJob(ctx context.Context, jobID, workerID, failure string, now time.Time) error {
	return s.finishDurableJob(ctx, jobID, workerID, "failed", failure, time.Time{}, now)
}

func (s *Store) RetryDurableJob(ctx context.Context, jobID, workerID, failure string, availableAt, now time.Time) error {
	if availableAt.IsZero() {
		return errors.New("retry availability is required")
	}
	return s.finishDurableJob(ctx, jobID, workerID, "ready", failure, availableAt.UTC(), now)
}

func (s *Store) finishDurableJob(ctx context.Context, jobID, workerID, state, failure string, availableAt, now time.Time) error {
	now = normalizedTime(now)
	if !safeWorkerID.MatchString(workerID) || (state != "succeeded" && state != "failed" && state != "ready") {
		return errors.New("durable job completion is invalid")
	}
	failure = sanitizeJobError(failure)
	stamp := now.Format(time.RFC3339Nano)
	availability := any(nil)
	if state == "ready" {
		availability = availableAt.Format(time.RFC3339Nano)
	}
	result, err := s.db.ExecContext(ctx, `UPDATE durable_jobs SET state = ?,
		available_at = COALESCE(?, available_at), lease_owner = NULL, lease_expires_at = NULL,
		heartbeat_at = NULL, last_error = NULLIF(?, ''), updated_at = ?
		WHERE id = ? AND state = 'leased' AND lease_owner = ? AND lease_expires_at > ?`,
		state, availability, failure, stamp, jobID, workerID, stamp)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return ErrResourceNotFound
	}
	return nil
}

func (s *Store) EnqueueOutbox(ctx context.Context, topic, deduplicationID string, payload json.RawMessage, now time.Time) (OutboxMessage, error) {
	now = normalizedTime(now)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return OutboxMessage{}, err
	}
	defer tx.Rollback()
	message, err := enqueueOutboxTx(ctx, tx, topic, deduplicationID, payload, now)
	if err != nil {
		return OutboxMessage{}, err
	}
	if err := tx.Commit(); err != nil {
		return OutboxMessage{}, err
	}
	return message, nil
}

func enqueueOutboxTx(ctx context.Context, tx *sql.Tx, topic, deduplicationID string, payload json.RawMessage, now time.Time) (OutboxMessage, error) {
	if !safeTopic.MatchString(topic) || !safeDedupeID.MatchString(deduplicationID) {
		return OutboxMessage{}, errors.New("outbox topic or deduplication id is invalid")
	}
	canonical, err := canonicalJSONObject(payload)
	if err != nil {
		return OutboxMessage{}, err
	}
	var existing OutboxMessage
	var storedPayload, created string
	err = tx.QueryRowContext(ctx, `SELECT id, topic, deduplication_id, payload_json, created_at, attempts
		FROM outbox WHERE deduplication_id = ?`, deduplicationID).
		Scan(&existing.ID, &existing.Topic, &existing.DeduplicationID, &storedPayload, &created, &existing.Attempts)
	if err == nil {
		if existing.Topic != topic || storedPayload != string(canonical) {
			return OutboxMessage{}, ErrVersionConflict
		}
		existing.Payload = json.RawMessage(storedPayload)
		existing.CreatedAt, err = time.Parse(time.RFC3339Nano, created)
		return existing, err
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return OutboxMessage{}, err
	}
	id, err := idgen.New("out")
	if err != nil {
		return OutboxMessage{}, err
	}
	now = normalizedTime(now)
	stamp := now.Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `INSERT INTO outbox
		(id, topic, deduplication_id, payload_json, created_at, available_at)
		VALUES (?, ?, ?, ?, ?, ?)`, id, topic, deduplicationID, string(canonical), stamp, stamp); err != nil {
		if constraintContains(err, "outbox.deduplication_id") {
			return OutboxMessage{}, ErrVersionConflict
		}
		return OutboxMessage{}, err
	}
	return OutboxMessage{ID: id, Topic: topic, DeduplicationID: deduplicationID, Payload: canonical, CreatedAt: now}, nil
}

func (s *Store) LeaseOutbox(ctx context.Context, publisherID string, limit int, leaseDuration time.Duration, now time.Time) ([]OutboxMessage, error) {
	now = normalizedTime(now)
	if !safeWorkerID.MatchString(publisherID) || limit < 1 || limit > 100 || leaseDuration < 5*time.Second || leaseDuration > 10*time.Minute {
		return nil, errors.New("outbox lease request is invalid")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	stamp := now.Format(time.RFC3339Nano)
	rows, err := tx.QueryContext(ctx, `SELECT id FROM outbox
		WHERE published_at IS NULL AND COALESCE(available_at, created_at) <= ?
		  AND (lease_expires_at IS NULL OR lease_expires_at <= ?)
		ORDER BY created_at, id LIMIT ?`, stamp, stamp, limit)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	expires := now.Add(leaseDuration).Format(time.RFC3339Nano)
	messages := make([]OutboxMessage, 0, len(ids))
	for _, id := range ids {
		result, err := tx.ExecContext(ctx, `UPDATE outbox SET lease_owner = ?, lease_expires_at = ?, attempts = attempts + 1
			WHERE id = ? AND published_at IS NULL AND (lease_expires_at IS NULL OR lease_expires_at <= ?)`,
			publisherID, expires, id, stamp)
		if err != nil {
			return nil, err
		}
		if changed, _ := result.RowsAffected(); changed != 1 {
			continue
		}
		var message OutboxMessage
		var payload, created string
		if err := tx.QueryRowContext(ctx, `SELECT id, topic, deduplication_id, payload_json, created_at, attempts
			FROM outbox WHERE id = ?`, id).Scan(&message.ID, &message.Topic, &message.DeduplicationID,
			&payload, &created, &message.Attempts); err != nil {
			return nil, err
		}
		message.Payload = json.RawMessage(payload)
		message.CreatedAt, err = time.Parse(time.RFC3339Nano, created)
		if err != nil {
			return nil, err
		}
		messages = append(messages, message)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return messages, nil
}

func (s *Store) MarkOutboxPublished(ctx context.Context, messageID, publisherID string, now time.Time) error {
	now = normalizedTime(now)
	stamp := now.Format(time.RFC3339Nano)
	result, err := s.db.ExecContext(ctx, `UPDATE outbox SET published_at = ?, lease_owner = NULL,
		lease_expires_at = NULL, last_error = NULL WHERE id = ? AND published_at IS NULL
		AND lease_owner = ? AND lease_expires_at > ?`, stamp, messageID, publisherID, stamp)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return ErrResourceNotFound
	}
	return nil
}

func (s *Store) RetryOutbox(ctx context.Context, messageID, publisherID, failure string, availableAt, now time.Time) error {
	now = normalizedTime(now)
	if availableAt.IsZero() || !availableAt.After(now) {
		return errors.New("outbox retry must be scheduled in the future")
	}
	failure = sanitizeJobError(failure)
	stamp := now.Format(time.RFC3339Nano)
	result, err := s.db.ExecContext(ctx, `UPDATE outbox SET available_at = ?, lease_owner = NULL,
		lease_expires_at = NULL, last_error = ? WHERE id = ? AND published_at IS NULL
		AND lease_owner = ? AND lease_expires_at > ?`, availableAt.UTC().Format(time.RFC3339Nano),
		failure, messageID, publisherID, stamp)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return ErrResourceNotFound
	}
	return nil
}

func durableJobByDedupeTx(ctx context.Context, tx *sql.Tx, dedupe string) (DurableJob, error) {
	return scanDurableJob(tx.QueryRowContext(ctx, `SELECT id, kind, deduplication_id, payload_json, state,
		available_at, lease_owner, lease_expires_at, heartbeat_at, attempts, last_error, created_at, updated_at
		FROM durable_jobs WHERE deduplication_id = ?`, dedupe))
}

func durableJobByIDTx(ctx context.Context, tx *sql.Tx, id string) (DurableJob, error) {
	return scanDurableJob(tx.QueryRowContext(ctx, `SELECT id, kind, deduplication_id, payload_json, state,
		available_at, lease_owner, lease_expires_at, heartbeat_at, attempts, last_error, created_at, updated_at
		FROM durable_jobs WHERE id = ?`, id))
}

func scanDurableJob(row *sql.Row) (DurableJob, error) {
	var job DurableJob
	var payload, available, created, updated string
	var owner, expires, heartbeat, lastError sql.NullString
	if err := row.Scan(&job.ID, &job.Kind, &job.DeduplicationID, &payload, &job.State, &available,
		&owner, &expires, &heartbeat, &job.Attempts, &lastError, &created, &updated); err != nil {
		return DurableJob{}, err
	}
	job.Payload = json.RawMessage(payload)
	job.LeaseOwner, job.LastError = owner.String, lastError.String
	var err error
	job.AvailableAt, err = time.Parse(time.RFC3339Nano, available)
	if err != nil {
		return DurableJob{}, err
	}
	job.CreatedAt, err = time.Parse(time.RFC3339Nano, created)
	if err != nil {
		return DurableJob{}, err
	}
	job.UpdatedAt, err = time.Parse(time.RFC3339Nano, updated)
	if err != nil {
		return DurableJob{}, err
	}
	if expires.Valid {
		value, parseErr := time.Parse(time.RFC3339Nano, expires.String)
		if parseErr != nil {
			return DurableJob{}, parseErr
		}
		job.LeaseExpiresAt = &value
	}
	if heartbeat.Valid {
		value, parseErr := time.Parse(time.RFC3339Nano, heartbeat.String)
		if parseErr != nil {
			return DurableJob{}, parseErr
		}
		job.HeartbeatAt = &value
	}
	return job, nil
}

func canonicalJSONObject(payload json.RawMessage) (json.RawMessage, error) {
	if len(payload) < 2 || len(payload) > maxJobPayloadBytes || !json.Valid(payload) {
		return nil, errors.New("job payload must be valid bounded JSON")
	}
	uniqueDecoder := json.NewDecoder(strings.NewReader(string(payload)))
	uniqueDecoder.UseNumber()
	if err := consumeUniqueJSONValue(uniqueDecoder, 0); err != nil {
		return nil, errors.New("job payload contains duplicate keys or excessive nesting")
	}
	if _, err := uniqueDecoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("job payload contains trailing data")
	}
	var value map[string]any
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil || value == nil {
		return nil, errors.New("job payload must be a JSON object")
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("canonicalize job payload: %w", err)
	}
	return canonical, nil
}

func consumeUniqueJSONValue(decoder *json.Decoder, depth int) error {
	if depth > 64 {
		return errors.New("maximum JSON nesting exceeded")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			if _, exists := seen[key]; exists {
				return errors.New("duplicate object key")
			}
			seen[key] = struct{}{}
			if err := consumeUniqueJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("object is not closed")
		}
		return nil
	case '[':
		for decoder.More() {
			if err := consumeUniqueJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("array is not closed")
		}
		return nil
	default:
		return errors.New("invalid JSON delimiter")
	}
}

func sanitizeJobError(value string) string {
	value = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' || r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			return ' '
		}
		return r
	}, value)
	value = strings.TrimSpace(value)
	if len(value) > 1000 {
		value = value[:1000]
	}
	return value
}
