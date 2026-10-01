package sqlite

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"plntir/core/internal/envelope"
	"plntir/core/internal/wazuhintegrity"
)

func (s *Store) AcceptWazuhProjection(
	ctx context.Context,
	signed envelope.Envelope,
	projection wazuhintegrity.HealthProjection,
	verifyKey ed25519.PublicKey,
	now time.Time,
) (bool, error) {
	if signed.Kind != "wazuh-health-v1" || signed.Source != "plntir-siem-01" ||
		projection.LastSequence != signed.Sequence || projection.ObservedAt != signed.Timestamp ||
		projection.LastSequence > math.MaxInt64 || wazuhintegrity.ValidateHealthProjection(projection) != nil {
		return false, wazuhintegrity.ErrProjectionAuthentication
	}
	if now.IsZero() {
		return false, wazuhintegrity.ErrProjectionAuthentication
	}
	expectedPayload, err := jsonMarshalProjection(projection)
	if err != nil || !bytes.Equal(expectedPayload, signed.Payload) {
		return false, wazuhintegrity.ErrProjectionAuthentication
	}
	payloadHash := sha256.Sum256(signed.Payload)
	if err := envelope.Verify(signed, verifyKey, envelope.VerifyOptions{
		Now: now, MaximumAge: wazuhintegrity.ProjectionMaximumAge,
		MaximumFuture: wazuhintegrity.ProjectionMaximumFuture,
	}); err != nil {
		return false, fmt.Errorf("%w: %v", wazuhintegrity.ErrProjectionAuthentication, err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	var existingKind, existingTimestamp, existingDeduplicationID string
	var existingPayloadHash []byte
	err = tx.QueryRowContext(ctx, `
		SELECT kind, timestamp, deduplication_id, payload_sha256
		FROM ingested_envelopes WHERE source = ? AND sequence = ?`,
		signed.Source, signed.Sequence,
	).Scan(&existingKind, &existingTimestamp, &existingDeduplicationID, &existingPayloadHash)
	if err == nil {
		if existingKind == signed.Kind && existingTimestamp == signed.Timestamp &&
			existingDeduplicationID == signed.DeduplicationID && bytes.Equal(existingPayloadHash, payloadHash[:]) {
			return false, nil
		}
		return false, wazuhintegrity.ErrProjectionStoreConflict
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	var duplicateCount int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM ingested_envelopes WHERE deduplication_id = ?`,
		signed.DeduplicationID).Scan(&duplicateCount); err != nil {
		return false, err
	}
	if duplicateCount != 0 {
		return false, wazuhintegrity.ErrProjectionStoreConflict
	}
	var lastSequence uint64
	var storedSequence int64
	err = tx.QueryRowContext(ctx, `SELECT last_sequence FROM wazuh_health_projection WHERE source = ?`,
		signed.Source).Scan(&storedSequence)
	if err == nil {
		lastSequence = uint64(storedSequence)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	if signed.Sequence != lastSequence+1 {
		return false, wazuhintegrity.ErrProjectionStoreConflict
	}
	if err := envelope.Verify(signed, verifyKey, envelope.VerifyOptions{
		Now: now, LastSequence: lastSequence,
		MaximumAge:    wazuhintegrity.ProjectionMaximumAge,
		MaximumFuture: wazuhintegrity.ProjectionMaximumFuture,
	}); err != nil {
		return false, fmt.Errorf("%w: %v", wazuhintegrity.ErrProjectionAuthentication, err)
	}
	receivedAt := now.UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO ingested_envelopes(
			source, sequence, deduplication_id, kind, timestamp, payload_sha256, received_at
		) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		signed.Source, signed.Sequence, signed.DeduplicationID, signed.Kind,
		signed.Timestamp, payloadHash[:], receivedAt,
	); err != nil {
		return false, fmt.Errorf("store Wazuh envelope: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO wazuh_health_projection(
			source, schema_version, state, observed_at, last_event_at, last_sequence,
			chain_hash, agent_id, rule_level, severity, envelope_deduplication_id, received_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, NULLIF(?, ''), ?, ?, ?, ?)
		ON CONFLICT(source) DO UPDATE SET
			schema_version = excluded.schema_version,
			state = excluded.state,
			observed_at = excluded.observed_at,
			last_event_at = excluded.last_event_at,
			last_sequence = excluded.last_sequence,
			chain_hash = excluded.chain_hash,
			agent_id = excluded.agent_id,
			rule_level = excluded.rule_level,
			severity = excluded.severity,
			envelope_deduplication_id = excluded.envelope_deduplication_id,
			received_at = excluded.received_at`,
		signed.Source, projection.SchemaVersion, projection.State, projection.ObservedAt,
		projection.LastEventAt, projection.LastSequence, projection.ChainHash, projection.AgentID,
		projection.RuleLevel, projection.Severity, signed.DeduplicationID, receivedAt,
	); err != nil {
		return false, fmt.Errorf("store Wazuh health projection: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func jsonMarshalProjection(projection wazuhintegrity.HealthProjection) ([]byte, error) {
	return json.Marshal(projection)
}
