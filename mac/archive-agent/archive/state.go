package archive

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const MaxStateBytes = 16 << 20

type PendingUpload struct {
	WorkID           string    `json:"work_id"`
	ObjectID         string    `json:"object_id"`
	NonceCounter     uint64    `json:"nonce_counter"`
	PayloadBytes     int64     `json:"payload_bytes"`
	PayloadSHA256    string    `json:"payload_sha256"`
	PlaintextSHA256  string    `json:"plaintext_sha256"`
	CiphertextSHA256 string    `json:"ciphertext_sha256"`
	ReservedAt       time.Time `json:"reserved_at"`
}

type ArchiveState struct {
	SchemaVersion    int                  `json:"schema_version"`
	DeviceID         string               `json:"device_id"`
	ArchiveID        string               `json:"archive_id"`
	ArchiveKeyID     string               `json:"archive_key_id"`
	Root             string               `json:"root"`
	PlanDigestSHA256 string               `json:"plan_digest_sha256"`
	NoncePrefixB64   string               `json:"nonce_prefix_b64"`
	NextNonceCounter uint64               `json:"next_nonce_counter"`
	Envelopes        KeyEnvelopes         `json:"key_envelopes"`
	Confirmed        map[string]ObjectRef `json:"confirmed"`
	Pending          *PendingUpload       `json:"pending,omitempty"`
	UpdatedAt        time.Time            `json:"updated_at"`
}

func NewArchiveState(deviceID, archiveID, archiveKeyID string, plan Plan, envelopes KeyEnvelopes, prefix [NoncePrefixBytes]byte, now time.Time) (ArchiveState, error) {
	if err := plan.Validate(); err != nil {
		return ArchiveState{}, err
	}
	if _, reusedKey := plan.PriorKeyEnvelopes[archiveKeyID]; reusedKey {
		return ArchiveState{}, errors.New("a new snapshot must not reuse a prior snapshot DEK")
	}
	state := ArchiveState{
		SchemaVersion:    SchemaVersion,
		DeviceID:         deviceID,
		ArchiveID:        archiveID,
		ArchiveKeyID:     archiveKeyID,
		Root:             plan.Root,
		PlanDigestSHA256: plan.DigestSHA256,
		NoncePrefixB64:   base64.RawStdEncoding.EncodeToString(prefix[:]),
		NextNonceCounter: 1,
		Envelopes:        envelopes,
		Confirmed:        make(map[string]ObjectRef),
		UpdatedAt:        now.UTC(),
	}
	if err := state.Validate(); err != nil {
		return ArchiveState{}, err
	}
	return state, nil
}

func (state ArchiveState) Validate() error {
	if state.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported archive state schema %d", state.SchemaVersion)
	}
	for label, value := range map[string]string{"device ID": state.DeviceID, "archive ID": state.ArchiveID, "archive key ID": state.ArchiveKeyID} {
		if !validOpaqueID(value, 128) {
			return fmt.Errorf("%s is invalid", label)
		}
	}
	if !path.IsAbs(state.Root) || path.Clean(state.Root) != state.Root || !validHexDigest(state.PlanDigestSHA256) {
		return errors.New("archive state root or plan digest is invalid")
	}
	prefix, err := state.NoncePrefix()
	if err != nil || prefix == [NoncePrefixBytes]byte{} {
		return errors.New("archive nonce prefix is invalid or all-zero")
	}
	if state.NextNonceCounter == 0 || state.UpdatedAt.IsZero() {
		return errors.New("archive state counters or timestamp are invalid")
	}
	if err := validateEnvelopes(state.Envelopes); err != nil {
		return err
	}
	usedCounters := make(map[uint64]struct{}, len(state.Confirmed)+1)
	for workID, object := range state.Confirmed {
		if !validHexDigest(workID) || !validObjectRef(object) {
			return errors.New("archive state contains an invalid confirmed object")
		}
		if object.DeviceID != state.DeviceID || object.ArchiveID != state.ArchiveID || object.ArchiveKeyID != state.ArchiveKeyID || object.WorkID != workID || object.NonceCounter >= state.NextNonceCounter {
			return errors.New("confirmed archive object has the wrong key context or counter")
		}
		if _, duplicate := usedCounters[object.NonceCounter]; duplicate {
			return errors.New("archive state reuses a nonce counter")
		}
		usedCounters[object.NonceCounter] = struct{}{}
	}
	if state.Pending != nil {
		pending := state.Pending
		if !validHexDigest(pending.WorkID) || !validOpaqueID(pending.ObjectID, 128) || pending.NonceCounter == 0 || pending.NonceCounter >= state.NextNonceCounter || pending.PayloadBytes <= recordHeaderBytes+GCMTagBytes || !validHexDigest(pending.PayloadSHA256) || !validHexDigest(pending.PlaintextSHA256) || !validHexDigest(pending.CiphertextSHA256) || pending.ReservedAt.IsZero() {
			return errors.New("archive pending reservation is invalid")
		}
		if _, confirmed := state.Confirmed[pending.WorkID]; confirmed {
			return errors.New("archive work is both pending and confirmed")
		}
		if _, duplicate := usedCounters[pending.NonceCounter]; duplicate {
			return errors.New("pending archive work reuses a nonce counter")
		}
	}
	return nil
}

func (state ArchiveState) NoncePrefix() ([NoncePrefixBytes]byte, error) {
	var prefix [NoncePrefixBytes]byte
	decoded, err := base64.RawStdEncoding.DecodeString(state.NoncePrefixB64)
	if err != nil || len(decoded) != NoncePrefixBytes {
		return prefix, errors.New("invalid nonce prefix encoding")
	}
	copy(prefix[:], decoded)
	return prefix, nil
}

func validateEnvelopes(envelopes KeyEnvelopes) error {
	if envelopes.KMSKeyReference == "" || envelopes.KMSAlgorithm == "" || envelopes.OfflineAlgorithm != "RSA-OAEP-SHA256" || !validHexDigest(envelopes.OfflineFingerprint) {
		return errors.New("archive key envelopes are incomplete")
	}
	for _, encoded := range []string{envelopes.KMSCiphertextB64, envelopes.OfflineCiphertextB64} {
		decoded, err := base64.RawStdEncoding.DecodeString(encoded)
		if err != nil || len(decoded) == 0 {
			return errors.New("archive key envelope is not canonical base64")
		}
	}
	return nil
}

func validHexDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && strings.ToLower(value) == value
}

func validOpaqueID(value string, maximum int) bool {
	if value == "" || len(value) > maximum {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '-' || character == '_' || character == '.' || character == ':' {
			continue
		}
		return false
	}
	return true
}

func validObjectRef(object ObjectRef) bool {
	return validOpaqueID(object.ObjectID, 128) && validOpaqueID(object.DeviceID, 128) && validOpaqueID(object.ArchiveID, 128) && validOpaqueID(object.ArchiveKeyID, 128) && validHexDigest(object.WorkID) && object.Offset >= 0 && object.PlaintextBytes > 0 && object.CiphertextBytes > object.PlaintextBytes && object.NonceCounter > 0 && validHexDigest(object.CiphertextHash)
}

type StateStore struct {
	Path string
}

func (store StateStore) Load() (ArchiveState, error) {
	directory, name, err := store.openDirectory()
	if err != nil {
		return ArchiveState{}, err
	}
	defer directory.Close()
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return ArchiveState{}, fmt.Errorf("open archive state: %w", err)
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		unix.Close(fd)
		return ArchiveState{}, errors.New("construct archive state descriptor")
	}
	defer file.Close()
	if err := requirePrivateRegularFile(file); err != nil {
		return ArchiveState{}, err
	}
	content, err := io.ReadAll(io.LimitReader(file, MaxStateBytes+1))
	if err != nil {
		return ArchiveState{}, err
	}
	if len(content) > MaxStateBytes {
		return ArchiveState{}, errors.New("archive state exceeds 16 MiB")
	}
	var state ArchiveState
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return ArchiveState{}, fmt.Errorf("decode archive state: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return ArchiveState{}, err
	}
	if err := state.Validate(); err != nil {
		return ArchiveState{}, err
	}
	return state, nil
}

func (store StateStore) Save(state ArchiveState) error {
	if err := state.Validate(); err != nil {
		return err
	}
	content, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	content = append(content, '\n')
	if len(content) > MaxStateBytes {
		return errors.New("archive state exceeds 16 MiB")
	}
	directory, name, err := store.openDirectory()
	if err != nil {
		return err
	}
	defer directory.Close()
	if err := validateExistingState(directory, name); err != nil {
		return err
	}
	random := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, random); err != nil {
		return err
	}
	temporary := "." + name + "." + hex.EncodeToString(random) + ".tmp"
	fd, err := unix.Openat(int(directory.Fd()), temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("create archive state temporary file: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			unix.Unlinkat(int(directory.Fd()), temporary, 0)
		}
	}()
	file := os.NewFile(uintptr(fd), temporary)
	if file == nil {
		unix.Close(fd)
		return errors.New("construct archive state temporary descriptor")
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(content); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := unix.Renameat(int(directory.Fd()), temporary, int(directory.Fd()), name); err != nil {
		return fmt.Errorf("atomically replace archive state: %w", err)
	}
	cleanup = false
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync archive state directory: %w", err)
	}
	return nil
}

func (store StateStore) openDirectory() (*os.File, string, error) {
	if !path.IsAbs(store.Path) || path.Clean(store.Path) != store.Path {
		return nil, "", errors.New("archive state path must be clean and absolute")
	}
	name := path.Base(store.Path)
	if !safeBaseName(name) {
		return nil, "", errors.New("archive state filename is unsafe")
	}
	directory, err := openRootNoFollow(path.Dir(store.Path))
	if err != nil {
		return nil, "", err
	}
	metadata, err := statFile(directory)
	if err != nil {
		directory.Close()
		return nil, "", err
	}
	if metadata.typeBits != unix.S_IFDIR || metadata.uid != uint32(os.Geteuid()) || metadata.mode&0o077 != 0 {
		directory.Close()
		return nil, "", errors.New("archive state directory must be owned by the process and inaccessible to group/other")
	}
	return directory, name, nil
}

func validateExistingState(directory *os.File, name string) error {
	metadata, err := statAtNoFollow(directory, name)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	if metadata.typeBits != unix.S_IFREG || metadata.uid != uint32(os.Geteuid()) || metadata.mode&0o777 != 0o600 {
		return errors.New("existing archive state must be a process-owned 0600 regular file")
	}
	return nil
}

func requirePrivateRegularFile(file *os.File) error {
	metadata, err := statFile(file)
	if err != nil {
		return err
	}
	if metadata.typeBits != unix.S_IFREG || metadata.uid != uint32(os.Geteuid()) || metadata.mode&0o777 != 0o600 {
		return errors.New("archive state must be a process-owned 0600 regular file")
	}
	return nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("archive state contains trailing JSON")
		}
		return err
	}
	return nil
}
