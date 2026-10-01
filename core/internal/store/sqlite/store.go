package sqlite

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"plntir/core/internal/domain"
	"plntir/core/internal/idgen"

	_ "modernc.org/sqlite"
)

const (
	MaxAccounts          = 10
	MaxDevices           = 25
	MaxLogicalPoolBytes  = int64(2_000_000_000_000)
	LargeTransferCutoff  = int64(1_600_000_000_000)
	MaxStandardFileBytes = int64(5_000_000_000)
	MaxMediaFileBytes    = int64(500_000_000_000)
	StandardPartBytes    = int64(16 << 20)
	MediaPartBytes       = int64(64 << 20)
	ChunkTagBytes        = int64(16)
)

var (
	ErrUsernameTaken    = errors.New("username has already been reserved")
	ErrVersionConflict  = errors.New("resource version conflict")
	ErrQuotaExceeded    = errors.New("logical storage quota exceeded")
	ErrLargeTransferCap = errors.New("large transfers are blocked at 80 percent logical usage")
	ErrMediaPermission  = errors.New("large media transfer requires a durable grant and managed Mac")
)

//go:embed migrations/*.sql
var migrations embed.FS

type Store struct {
	db *sql.DB
}

type Account struct {
	ID                string
	UsernameDisplay   string
	UsernameCanonical string
	State             string
	Version           int64
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

type UploadRequest struct {
	OwnerAccountID  string
	Filename        string
	MediaKind       string
	PlaintextBytes  int64
	ManagedMac      bool
	LargeMediaGrant bool
	ManifestSHA256  [sha256.Size]byte
	NoncePrefix     [4]byte
	KMSEnvelope     KeyEnvelopeInput
	OfflineEnvelope KeyEnvelopeInput
	Now             time.Time
}

type KeyEnvelopeInput struct {
	Algorithm    string
	KeyReference string
	Ciphertext   []byte
}

type Upload struct {
	FileID                  string
	FileVersionID           string
	UploadSessionID         string
	ReservationID           string
	ObjectKey               string
	PartSizeBytes           int64
	ExpectedParts           int64
	ExpectedCiphertextBytes int64
	ExpiresAt               time.Time
}

type AuditEntry struct {
	Sequence     int64
	ID           string
	OccurredAt   time.Time
	ActorID      string
	Action       string
	TargetID     string
	Success      bool
	DetailsJSON  []byte
	PreviousHash [32]byte
	EntryHash    [32]byte
}

func Open(ctx context.Context, path string) (*Store, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("SQLite path must be absolute")
	}
	path = filepath.Clean(path)
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("SQLite database must be a regular non-symlink file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("stat SQLite database: %w", err)
	}
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return nil, fmt.Errorf("create SQLite directory: %w", err)
	}
	if err := rejectSymlinkPath(parent); err != nil {
		return nil, err
	}

	dsn := "file:" + url.PathEscape(path) + "?_pragma=busy_timeout%285000%29"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open SQLite: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	store := &Store{db: db}
	if err := store.configure(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("protect SQLite database: %w", err)
	}
	if err := store.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func rejectSymlinkPath(path string) error {
	current := path
	for {
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("stat SQLite parent path: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("SQLite parent path contains symlink %q", current)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
		current = parent
	}
}

func (s *Store) configure(ctx context.Context) error {
	for _, statement := range []string{
		"PRAGMA foreign_keys = ON",
		"PRAGMA journal_mode = WAL",
		"PRAGMA synchronous = FULL",
		"PRAGMA busy_timeout = 5000",
		"PRAGMA trusted_schema = OFF",
		"PRAGMA temp_store = MEMORY",
	} {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("configure SQLite with %q: %w", statement, err)
		}
	}
	var mode string
	if err := s.db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode); err != nil {
		return fmt.Errorf("read SQLite journal mode: %w", err)
	}
	if !strings.EqualFold(mode, "wal") {
		return fmt.Errorf("SQLite refused WAL mode: %q", mode)
	}
	return nil
}

func (s *Store) migrate(ctx context.Context) error {
	entries, err := fs.ReadDir(migrations, "migrations")
	if err != nil {
		return fmt.Errorf("read embedded migrations: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for index, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		version := index + 1
		contents, err := migrations.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return fmt.Errorf("read migration %q: %w", entry.Name(), err)
		}
		digest := sha256.Sum256(contents)
		var applied int
		err = s.db.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='schema_migrations'").Scan(&applied)
		if err != nil {
			return fmt.Errorf("inspect migrations table: %w", err)
		}
		if applied == 1 {
			var storedName string
			var storedDigest []byte
			err = s.db.QueryRowContext(ctx, "SELECT name, sha256 FROM schema_migrations WHERE version = ?", version).Scan(&storedName, &storedDigest)
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("inspect migration %d: %w", version, err)
			}
			if err == nil {
				if storedName != entry.Name() || len(storedDigest) != sha256.Size || !bytes.Equal(storedDigest, digest[:]) {
					return fmt.Errorf("applied migration %d (%s) failed its integrity check", version, entry.Name())
				}
				continue
			}
		}
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, string(contents)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("apply migration %q: %w", entry.Name(), err)
		}
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO schema_migrations(version, name, sha256, applied_at) VALUES (?, ?, ?, ?)",
			version, entry.Name(), digest[:], time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("record migration %q: %w", entry.Name(), err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %q: %w", entry.Name(), err)
		}
	}
	return nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) QuickCheck(ctx context.Context) error {
	var result string
	if err := s.db.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&result); err != nil {
		return fmt.Errorf("SQLite quick_check: %w", err)
	}
	if result != "ok" {
		return fmt.Errorf("SQLite quick_check failed: %s", result)
	}
	return nil
}

func (s *Store) CreateAccount(ctx context.Context, rawUsername string, now time.Time) (Account, error) {
	username, err := domain.ParseUsername(rawUsername)
	if err != nil {
		return Account{}, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	now = now.UTC()
	id, err := idgen.New("usr")
	if err != nil {
		return Account{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Account{}, err
	}
	defer tx.Rollback()
	stamp := now.Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `INSERT INTO accounts
		(id, username_display, username_canonical, state, version, created_at, updated_at)
		VALUES (?, ?, ?, 'active', 1, ?, ?)`, id, username.Display, username.Canonical, stamp, stamp); err != nil {
		if constraintContains(err, "accounts.username_canonical") || constraintContains(err, "reserved_usernames.username_canonical") {
			return Account{}, ErrUsernameTaken
		}
		return Account{}, fmt.Errorf("insert account: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO reserved_usernames
		(username_canonical, username_display, owner_account_id, reserved_at) VALUES (?, ?, ?, ?)`,
		username.Canonical, username.Display, id, stamp); err != nil {
		if constraintContains(err, "reserved_usernames.username_canonical") {
			return Account{}, ErrUsernameTaken
		}
		return Account{}, fmt.Errorf("reserve username: %w", err)
	}
	if _, err := appendAuditTx(ctx, tx, "system", "account.create", id, true, map[string]any{"username": username.Display}, now); err != nil {
		return Account{}, err
	}
	if err := tx.Commit(); err != nil {
		return Account{}, err
	}
	return Account{ID: id, UsernameDisplay: username.Display, UsernameCanonical: username.Canonical, State: "active", Version: 1, CreatedAt: now, UpdatedAt: now}, nil
}

func (s *Store) RenameAccount(ctx context.Context, accountID, rawUsername string, expectedVersion int64, now time.Time) (Account, error) {
	username, err := domain.ParseUsername(rawUsername)
	if err != nil {
		return Account{}, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	now = now.UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Account{}, err
	}
	defer tx.Rollback()
	var current Account
	var createdAt, updatedAt string
	if err := tx.QueryRowContext(ctx, `SELECT id, username_display, username_canonical, state, version, created_at, updated_at
		FROM accounts WHERE id = ?`, accountID).Scan(&current.ID, &current.UsernameDisplay, &current.UsernameCanonical, &current.State, &current.Version, &createdAt, &updatedAt); err != nil {
		return Account{}, err
	}
	if current.State != "active" || current.Version != expectedVersion {
		return Account{}, ErrVersionConflict
	}
	var owner string
	err = tx.QueryRowContext(ctx, "SELECT owner_account_id FROM reserved_usernames WHERE username_canonical = ?", username.Canonical).Scan(&owner)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return Account{}, err
	}
	if err == nil && owner != accountID {
		return Account{}, ErrUsernameTaken
	}
	stamp := now.Format(time.RFC3339Nano)
	if errors.Is(err, sql.ErrNoRows) {
		if _, err := tx.ExecContext(ctx, `INSERT INTO reserved_usernames
			(username_canonical, username_display, owner_account_id, reserved_at) VALUES (?, ?, ?, ?)`,
			username.Canonical, username.Display, accountID, stamp); err != nil {
			if constraintContains(err, "reserved_usernames.username_canonical") {
				return Account{}, ErrUsernameTaken
			}
			return Account{}, err
		}
	}
	result, err := tx.ExecContext(ctx, `UPDATE accounts SET username_display = ?, username_canonical = ?,
		version = version + 1, updated_at = ? WHERE id = ? AND version = ? AND state = 'active'`,
		username.Display, username.Canonical, stamp, accountID, expectedVersion)
	if err != nil {
		if constraintContains(err, "accounts.username_canonical") {
			return Account{}, ErrUsernameTaken
		}
		return Account{}, err
	}
	changed, _ := result.RowsAffected()
	if changed != 1 {
		return Account{}, ErrVersionConflict
	}
	if _, err := appendAuditTx(ctx, tx, accountID, "account.rename", accountID, true,
		map[string]any{"from": current.UsernameDisplay, "to": username.Display}, now); err != nil {
		return Account{}, err
	}
	if err := tx.Commit(); err != nil {
		return Account{}, err
	}
	current.UsernameDisplay = username.Display
	current.UsernameCanonical = username.Canonical
	current.Version++
	current.UpdatedAt = now
	current.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	return current, nil
}

func (s *Store) StartUpload(ctx context.Context, request UploadRequest) (Upload, error) {
	if request.Now.IsZero() {
		request.Now = time.Now().UTC()
	}
	request.Now = request.Now.UTC()
	request.Filename = strings.TrimSpace(request.Filename)
	if request.Filename == "" || len(request.Filename) > 1024 || strings.ContainsAny(request.Filename, "\x00/\\") {
		return Upload{}, errors.New("invalid filename")
	}
	if request.PlaintextBytes <= 0 {
		return Upload{}, errors.New("file size must be positive")
	}
	if request.MediaKind != "standard" && request.MediaKind != "image" && request.MediaKind != "video" {
		return Upload{}, errors.New("invalid media kind")
	}
	isLargeMedia := request.MediaKind != "standard" && request.PlaintextBytes > MaxStandardFileBytes
	if request.MediaKind == "standard" && request.PlaintextBytes > MaxStandardFileBytes {
		return Upload{}, errors.New("standard files are limited to 5 GB")
	}
	if request.PlaintextBytes > MaxMediaFileBytes {
		return Upload{}, errors.New("files are limited to 500 GB")
	}
	if isLargeMedia && (!request.ManagedMac || !request.LargeMediaGrant) {
		return Upload{}, ErrMediaPermission
	}
	if err := validateKeyEnvelope("aws-kms", request.KMSEnvelope); err != nil {
		return Upload{}, err
	}
	if err := validateKeyEnvelope("offline-recovery", request.OfflineEnvelope); err != nil {
		return Upload{}, err
	}

	fileID, err := idgen.New("file")
	if err != nil {
		return Upload{}, err
	}
	versionID, err := idgen.New("fver")
	if err != nil {
		return Upload{}, err
	}
	uploadID, err := idgen.New("upl")
	if err != nil {
		return Upload{}, err
	}
	reservationID, err := idgen.New("qres")
	if err != nil {
		return Upload{}, err
	}
	objectID, err := idgen.New("obj")
	if err != nil {
		return Upload{}, err
	}
	objectKey := "objects/" + objectID
	partSize := StandardPartBytes
	if isLargeMedia {
		partSize = MediaPartBytes
	}
	expectedParts := (request.PlaintextBytes + partSize - 1) / partSize
	if expectedParts > 10000 {
		partSize = (request.PlaintextBytes + 9999) / 10000
		if isLargeMedia && partSize < MediaPartBytes {
			partSize = MediaPartBytes
		}
		expectedParts = (request.PlaintextBytes + partSize - 1) / partSize
	}
	expectedCiphertextBytes := request.PlaintextBytes + expectedParts*ChunkTagBytes
	expires := request.Now.Add(24 * time.Hour)
	immutableUntil := request.Now.Add(30 * 24 * time.Hour)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Upload{}, err
	}
	defer tx.Rollback()
	var state string
	if err := tx.QueryRowContext(ctx, "SELECT state FROM accounts WHERE id = ?", request.OwnerAccountID).Scan(&state); err != nil {
		return Upload{}, err
	}
	if state != "active" {
		return Upload{}, errors.New("owner account is not active")
	}
	var allocated int64
	if err := tx.QueryRowContext(ctx, `SELECT
		COALESCE((SELECT sum(logical_size_bytes) FROM files WHERE state IN ('active', 'trashed', 'deletion_pending')), 0) +
		COALESCE((SELECT sum(bytes) FROM quota_reservations WHERE state = 'active' AND expires_at > ?), 0)`,
		request.Now.Format(time.RFC3339Nano)).Scan(&allocated); err != nil {
		return Upload{}, err
	}
	if isLargeMedia && allocated >= LargeTransferCutoff {
		return Upload{}, ErrLargeTransferCap
	}
	if request.PlaintextBytes > MaxLogicalPoolBytes-allocated {
		return Upload{}, ErrQuotaExceeded
	}
	stamp := request.Now.Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `INSERT INTO files
		(id, owner_account_id, filename, media_kind, logical_size_bytes, state, version, current_version_id, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, 'uploading', 1, ?, ?, ?)`,
		fileID, request.OwnerAccountID, request.Filename, request.MediaKind, request.PlaintextBytes, versionID, stamp, stamp); err != nil {
		return Upload{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO file_versions
		(id, file_id, version_number, object_key, ciphertext_size_bytes, plaintext_size_bytes, chunk_size_bytes, scan_state, immutable_until, created_at)
		VALUES (?, ?, 1, ?, ?, ?, ?, 'pending_upload', ?, ?)`,
		versionID, fileID, objectKey, expectedCiphertextBytes, request.PlaintextBytes, partSize, immutableUntil.Format(time.RFC3339Nano), stamp); err != nil {
		return Upload{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE file_versions SET manifest_sha256 = ?, nonce_prefix = ? WHERE id = ?`,
		request.ManifestSHA256[:], request.NoncePrefix[:], versionID); err != nil {
		return Upload{}, err
	}
	for provider, envelope := range map[string]KeyEnvelopeInput{
		"aws-kms": request.KMSEnvelope, "offline-recovery": request.OfflineEnvelope,
	} {
		if _, err := tx.ExecContext(ctx, `INSERT INTO key_envelopes
			(file_version_id, provider, algorithm, key_reference, ciphertext, created_at)
			VALUES (?, ?, ?, ?, ?, ?)`, versionID, provider, envelope.Algorithm,
			envelope.KeyReference, envelope.Ciphertext, stamp); err != nil {
			return Upload{}, fmt.Errorf("store %s key envelope: %w", provider, err)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO quota_reservations
		(id, owner_account_id, file_id, bytes, state, created_at, expires_at)
		VALUES (?, ?, ?, ?, 'active', ?, ?)`, reservationID, request.OwnerAccountID, fileID,
		request.PlaintextBytes, stamp, expires.Format(time.RFC3339Nano)); err != nil {
		return Upload{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO upload_sessions
		(id, file_version_id, expected_parts, part_size_bytes, state, created_at, updated_at, expires_at)
		VALUES (?, ?, ?, ?, 'starting', ?, ?, ?)`, uploadID, versionID, expectedParts, partSize,
		stamp, stamp, expires.Format(time.RFC3339Nano)); err != nil {
		return Upload{}, err
	}
	if _, err := appendAuditTx(ctx, tx, request.OwnerAccountID, "upload.start", fileID, true,
		map[string]any{"bytes": request.PlaintextBytes, "kind": request.MediaKind}, request.Now); err != nil {
		return Upload{}, err
	}
	if err := tx.Commit(); err != nil {
		return Upload{}, err
	}
	return Upload{
		FileID: fileID, FileVersionID: versionID, UploadSessionID: uploadID,
		ReservationID: reservationID, ObjectKey: objectKey, PartSizeBytes: partSize,
		ExpectedParts: expectedParts, ExpectedCiphertextBytes: expectedCiphertextBytes, ExpiresAt: expires,
	}, nil
}

func validateKeyEnvelope(provider string, envelope KeyEnvelopeInput) error {
	if envelope.KeyReference == "" || len(envelope.KeyReference) > 512 || strings.ContainsAny(envelope.KeyReference, "\x00\r\n") {
		return fmt.Errorf("%s key reference is invalid", provider)
	}
	switch provider {
	case "aws-kms":
		if envelope.Algorithm != "SYMMETRIC_DEFAULT" || len(envelope.Ciphertext) < 1 || len(envelope.Ciphertext) > 6144 {
			return errors.New("AWS KMS envelope is invalid")
		}
	case "offline-recovery":
		if envelope.Algorithm != "X25519-HKDF-SHA256-AES-256-GCM" || len(envelope.Ciphertext) < 48 || len(envelope.Ciphertext) > 4096 {
			return errors.New("offline recovery envelope is invalid")
		}
	default:
		return errors.New("unknown key envelope provider")
	}
	return nil
}

func (s *Store) AppendAudit(ctx context.Context, actor, action, target string, success bool, details map[string]any, now time.Time) (AuditEntry, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AuditEntry{}, err
	}
	defer tx.Rollback()
	entry, err := appendAuditTx(ctx, tx, actor, action, target, success, details, now)
	if err != nil {
		return AuditEntry{}, err
	}
	if err := tx.Commit(); err != nil {
		return AuditEntry{}, err
	}
	return entry, nil
}

func appendAuditTx(ctx context.Context, tx *sql.Tx, actor, action, target string, success bool, details map[string]any, now time.Time) (AuditEntry, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	now = now.UTC()
	if actor == "" || action == "" || target == "" {
		return AuditEntry{}, errors.New("audit actor, action, and target are required")
	}
	if details == nil {
		details = map[string]any{}
	}
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		return AuditEntry{}, fmt.Errorf("encode audit details: %w", err)
	}
	entry := AuditEntry{ActorID: actor, Action: action, TargetID: target, Success: success, DetailsJSON: detailsJSON, OccurredAt: now}
	entry.ID, err = idgen.New("aud")
	if err != nil {
		return AuditEntry{}, err
	}
	var previous []byte
	var lastSequence int64
	err = tx.QueryRowContext(ctx, "SELECT sequence, entry_hash FROM audit_log ORDER BY sequence DESC LIMIT 1").Scan(&lastSequence, &previous)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return AuditEntry{}, err
	}
	if len(previous) == 32 {
		copy(entry.PreviousHash[:], previous)
	}
	entry.Sequence = lastSequence + 1
	entry.EntryHash = hashAuditEntry(entry)
	stamp := now.Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_log
		(sequence, id, occurred_at, actor_id, action, target_id, success, details_json, previous_hash, entry_hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.Sequence, entry.ID, stamp, actor, action, target, boolInt(success), string(detailsJSON), entry.PreviousHash[:], entry.EntryHash[:]); err != nil {
		return AuditEntry{}, fmt.Errorf("append audit: %w", err)
	}
	return entry, nil
}

func hashAuditEntry(entry AuditEntry) [32]byte {
	hash := sha256.New()
	hash.Write([]byte("plntir-audit-v1\x00"))
	hash.Write(entry.PreviousHash[:])
	var sequence [8]byte
	binary.BigEndian.PutUint64(sequence[:], uint64(entry.Sequence))
	hash.Write(sequence[:])
	for _, value := range []string{
		entry.ID,
		entry.OccurredAt.UTC().Format(time.RFC3339Nano),
		entry.ActorID,
		entry.Action,
		entry.TargetID,
	} {
		writeLengthPrefixed(hash, []byte(value))
	}
	if entry.Success {
		hash.Write([]byte{1})
	} else {
		hash.Write([]byte{0})
	}
	writeLengthPrefixed(hash, entry.DetailsJSON)
	var result [32]byte
	copy(result[:], hash.Sum(nil))
	return result
}

type byteWriter interface{ Write([]byte) (int, error) }

func writeLengthPrefixed(writer byteWriter, value []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = writer.Write(length[:])
	_, _ = writer.Write(value)
}

func (s *Store) VerifyAuditChain(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT sequence, id, occurred_at, actor_id, action, target_id,
		success, details_json, previous_hash, entry_hash FROM audit_log ORDER BY sequence`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var previous [32]byte
	var expectedSequence int64 = 1
	for rows.Next() {
		var entry AuditEntry
		var stamp string
		var success int
		var previousBytes, hashBytes []byte
		if err := rows.Scan(&entry.Sequence, &entry.ID, &stamp, &entry.ActorID, &entry.Action, &entry.TargetID,
			&success, &entry.DetailsJSON, &previousBytes, &hashBytes); err != nil {
			return err
		}
		entry.Success = success == 1
		entry.OccurredAt, err = time.Parse(time.RFC3339Nano, stamp)
		if err != nil || len(previousBytes) != 32 || len(hashBytes) != 32 {
			return fmt.Errorf("invalid audit entry %d encoding", entry.Sequence)
		}
		copy(entry.PreviousHash[:], previousBytes)
		copy(entry.EntryHash[:], hashBytes)
		if entry.Sequence != expectedSequence || entry.PreviousHash != previous || hashAuditEntry(entry) != entry.EntryHash {
			return fmt.Errorf("audit chain mismatch at sequence %d", entry.Sequence)
		}
		previous = entry.EntryHash
		expectedSequence++
	}
	return rows.Err()
}

func (s *Store) DBForTests() *sql.DB { return s.db }

func constraintContains(err error, value string) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), strings.ToLower(value))
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
