package wazuhintegrity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const maxJournalStateBytes = 16 << 10

var recordFilenamePattern = regexp.MustCompile(`^([0-9]{20})-([A-Za-z0-9_-]{43})\.json$`)

type ReceiptKind string

const (
	ArchiveReceipt    ReceiptKind = "archive-receipts"
	AlertReceipt      ReceiptKind = "alert-receipts"
	ProjectionReceipt ReceiptKind = "projection-receipts"
)

var receiptKinds = []ReceiptKind{ArchiveReceipt, AlertReceipt, ProjectionReceipt}

type JournalState struct {
	SchemaVersion int    `json:"schema_version"`
	LastSequence  uint64 `json:"last_sequence"`
	ChainHash     string `json:"chain_hash"`
	UpdatedAt     string `json:"updated_at"`
}

type Journal struct {
	root       string
	state      JournalState
	mu         sync.Mutex
	deliveryMu sync.Mutex
}

type JournalItem struct {
	Path   string
	Record Record
	Body   []byte
}

func OpenJournal(root string, now time.Time) (*Journal, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || now.IsZero() {
		return nil, errors.New("journal root must be a clean absolute path and time is required")
	}
	if err := requirePrivateDirectory(root); err != nil {
		return nil, err
	}
	for _, name := range []string{"pending", "delivered", string(ArchiveReceipt), string(AlertReceipt), string(ProjectionReceipt), "anchors"} {
		path := filepath.Join(root, name)
		if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("create journal directory: %w", err)
		}
		if err := requirePrivateDirectory(path); err != nil {
			return nil, err
		}
	}
	journal := &Journal{root: root}
	state, err := journal.loadState()
	if errors.Is(err, os.ErrNotExist) {
		for _, name := range []string{"delivered", string(ArchiveReceipt), string(AlertReceipt), string(ProjectionReceipt), "anchors"} {
			entries, readErr := os.ReadDir(filepath.Join(root, name))
			if readErr != nil || len(entries) != 0 {
				return nil, errors.New("journal state is missing while delivery or anchor history exists")
			}
		}
		zero := [sha256.Size]byte{}
		state = JournalState{
			SchemaVersion: SchemaVersion,
			ChainHash:     base64.RawURLEncoding.EncodeToString(zero[:]),
			UpdatedAt:     now.UTC().Format(time.RFC3339Nano),
		}
		if err := journal.saveState(state); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	journal.state = state
	if err := journal.validateAndRecover(now); err != nil {
		return nil, err
	}
	return journal, nil
}

func (journal *Journal) Append(raw []byte, receivedAt time.Time) (JournalItem, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	previous, err := decodeHash(journal.state.ChainHash)
	if err != nil {
		return JournalItem{}, err
	}
	record, err := NewRecord(journal.state.LastSequence+1, previous, raw, receivedAt)
	if err != nil {
		return JournalItem{}, err
	}
	body, err := record.Marshal()
	if err != nil {
		return JournalItem{}, err
	}
	name := journalRecordName(record)
	path := filepath.Join(journal.root, "pending", name)
	if err := createPrivateImmutable(path, body); err != nil {
		return JournalItem{}, err
	}
	next := JournalState{
		SchemaVersion: SchemaVersion,
		LastSequence:  record.Sequence,
		ChainHash:     record.EntryHash,
		UpdatedAt:     receivedAt.UTC().Format(time.RFC3339Nano),
	}
	if err := journal.saveState(next); err != nil {
		return JournalItem{}, fmt.Errorf("record is durable but journal state update failed: %w", err)
	}
	journal.state = next
	return JournalItem{Path: path, Record: record, Body: body}, nil
}

func (journal *Journal) Pending() ([]JournalItem, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	return journal.pendingLocked()
}

func (journal *Journal) State() JournalState {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	return journal.state
}

func (journal *Journal) PrepareDailyAnchor(now time.Time, privateKey ed25519.PrivateKey) (DailyAnchor, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if now.IsZero() || len(privateKey) != ed25519.PrivateKeySize || journal.state.LastSequence == 0 {
		return DailyAnchor{}, errors.New("cannot prepare an anchor before the journal has a signed state")
	}
	date := now.UTC().Format(time.DateOnly)
	path := filepath.Join(journal.root, "anchors", date+".json")
	if _, err := os.Lstat(path); err == nil {
		content, err := readPrivateFile(path, 16<<10)
		if err != nil {
			return DailyAnchor{}, err
		}
		var anchor DailyAnchor
		decoder := json.NewDecoder(bytes.NewReader(content))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&anchor); err != nil || ensureEOF(decoder) != nil {
			return DailyAnchor{}, errors.New("stored daily anchor is invalid")
		}
		canonical, err := anchor.Marshal()
		publicKey, ok := privateKey.Public().(ed25519.PublicKey)
		if err != nil || !ok || !bytes.Equal(canonical, content) || anchor.Date != date || VerifyDailyAnchor(anchor, publicKey) != nil {
			return DailyAnchor{}, errors.New("stored daily anchor is noncanonical, mismatched, or tampered")
		}
		return anchor, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return DailyAnchor{}, err
	}
	chainHash, err := decodeHash(journal.state.ChainHash)
	if err != nil {
		return DailyAnchor{}, err
	}
	anchor, err := SignDailyAnchor(journal.state.LastSequence, chainHash, now, privateKey)
	if err != nil {
		return DailyAnchor{}, err
	}
	body, err := anchor.Marshal()
	if err != nil {
		return DailyAnchor{}, err
	}
	if err := createPrivateImmutable(path, body); err != nil {
		return DailyAnchor{}, err
	}
	return anchor, nil
}

func (journal *Journal) MarkDelivered(record Record) error {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if err := record.Validate(); err != nil || record.Sequence > journal.state.LastSequence {
		return errors.New("cannot deliver an invalid or future record")
	}
	name := journalRecordName(record)
	source := filepath.Join(journal.root, "pending", name)
	destination := filepath.Join(journal.root, "delivered", name)
	sourceInfo, err := os.Lstat(source)
	if err != nil || !privateRegularFile(sourceInfo) {
		return errors.New("pending journal record is missing or invalid")
	}
	if err := os.Link(source, destination); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("publish delivery receipt: %w", err)
		}
		sourceInfo, sourceErr := os.Lstat(source)
		destinationInfo, destinationErr := os.Lstat(destination)
		if sourceErr != nil || destinationErr != nil || !os.SameFile(sourceInfo, destinationInfo) {
			return errors.New("a conflicting delivery receipt already exists")
		}
	}
	if err := syncDirectory(filepath.Join(journal.root, "delivered")); err != nil {
		return err
	}
	if err := os.Remove(source); err != nil {
		return fmt.Errorf("remove delivered pending link: %w", err)
	}
	return syncDirectory(filepath.Join(journal.root, "pending"))
}

func (journal *Journal) HasReceipt(record Record, kind ReceiptKind) (bool, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if !validReceiptKind(kind) || record.Validate() != nil || record.Sequence > journal.state.LastSequence {
		return false, errors.New("cannot inspect an invalid delivery receipt")
	}
	source := filepath.Join(journal.root, "pending", journalRecordName(record))
	receipt := filepath.Join(journal.root, string(kind), journalRecordName(record))
	sourceInfo, err := os.Lstat(source)
	if err != nil || !privateRegularFile(sourceInfo) {
		return false, errors.New("pending journal record is missing or invalid")
	}
	receiptInfo, err := os.Lstat(receipt)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || !privateRegularFile(receiptInfo) || !os.SameFile(sourceInfo, receiptInfo) {
		return false, errors.New("delivery receipt does not reference the pending record")
	}
	return true, nil
}

func (journal *Journal) MarkReceipt(record Record, kind ReceiptKind) error {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if !validReceiptKind(kind) || record.Validate() != nil || record.Sequence > journal.state.LastSequence {
		return errors.New("cannot publish an invalid delivery receipt")
	}
	name := journalRecordName(record)
	source := filepath.Join(journal.root, "pending", name)
	destination := filepath.Join(journal.root, string(kind), name)
	sourceInfo, err := os.Lstat(source)
	if err != nil || !privateRegularFile(sourceInfo) {
		return errors.New("pending journal record is missing or invalid")
	}
	if err := os.Link(source, destination); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("publish delivery receipt: %w", err)
		}
		receiptInfo, receiptErr := os.Lstat(destination)
		if receiptErr != nil || !privateRegularFile(receiptInfo) || !os.SameFile(sourceInfo, receiptInfo) {
			return errors.New("a conflicting delivery receipt already exists")
		}
	}
	return syncDirectory(filepath.Join(journal.root, string(kind)))
}

func validReceiptKind(kind ReceiptKind) bool {
	for _, allowed := range receiptKinds {
		if kind == allowed {
			return true
		}
	}
	return false
}

func (journal *Journal) loadState() (JournalState, error) {
	path := filepath.Join(journal.root, "state.json")
	info, err := os.Lstat(path)
	if err != nil {
		return JournalState{}, err
	}
	if !privateRegularFile(info) {
		return JournalState{}, errors.New("journal state must be a private owned regular file")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return JournalState{}, err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !privateRegularFile(openedInfo) {
		return JournalState{}, errors.New("opened journal state is not a private owned regular file")
	}
	content, err := io.ReadAll(io.LimitReader(file, maxJournalStateBytes+1))
	if err != nil || len(content) > maxJournalStateBytes {
		return JournalState{}, errors.New("journal state is unreadable or oversized")
	}
	var state JournalState
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return JournalState{}, errors.New("journal state JSON is invalid")
	}
	if err := ensureEOF(decoder); err != nil {
		return JournalState{}, err
	}
	if err := state.Validate(); err != nil {
		return JournalState{}, err
	}
	return state, nil
}

func (state JournalState) Validate() error {
	if state.SchemaVersion != SchemaVersion {
		return errors.New("journal state schema is invalid")
	}
	if _, err := decodeHash(state.ChainHash); err != nil {
		return errors.New("journal state chain hash is invalid")
	}
	stamp, err := time.Parse(time.RFC3339Nano, state.UpdatedAt)
	if err != nil || stamp.IsZero() {
		return errors.New("journal state update time is invalid")
	}
	return nil
}

func (journal *Journal) saveState(state JournalState) error {
	if err := state.Validate(); err != nil {
		return err
	}
	content, err := json.Marshal(state)
	if err != nil {
		return err
	}
	content = append(content, '\n')
	random := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, random); err != nil {
		return err
	}
	temporary := filepath.Join(journal.root, ".state."+hex.EncodeToString(random)+".tmp")
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(temporary)
		}
	}()
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
	if err := os.Rename(temporary, filepath.Join(journal.root, "state.json")); err != nil {
		return err
	}
	cleanup = false
	return syncDirectory(journal.root)
}

func (journal *Journal) validateAndRecover(now time.Time) error {
	items, err := journal.pendingLocked()
	if err != nil {
		return err
	}
	bySequence := make(map[uint64]Record, len(items))
	for _, item := range items {
		if _, duplicate := bySequence[item.Record.Sequence]; duplicate {
			return errors.New("journal contains duplicate record sequences")
		}
		bySequence[item.Record.Sequence] = item.Record
	}
	for index := 1; index < len(items); index++ {
		previous := items[index-1].Record
		current := items[index].Record
		if current.Sequence == previous.Sequence+1 && current.PreviousHash != previous.EntryHash {
			return errors.New("adjacent pending records do not form one hash chain")
		}
	}
	for {
		next, exists := bySequence[journal.state.LastSequence+1]
		if !exists {
			break
		}
		if next.PreviousHash != journal.state.ChainHash {
			return errors.New("orphan record does not extend the durable hash chain")
		}
		journal.state = JournalState{
			SchemaVersion: SchemaVersion,
			LastSequence:  next.Sequence,
			ChainHash:     next.EntryHash,
			UpdatedAt:     now.UTC().Format(time.RFC3339Nano),
		}
	}
	for sequence := range bySequence {
		if sequence > journal.state.LastSequence {
			return errors.New("journal has a gap beyond its durable state")
		}
	}
	diskState, err := journal.loadState()
	if err != nil {
		return err
	}
	if diskState.LastSequence != journal.state.LastSequence || diskState.ChainHash != journal.state.ChainHash {
		return journal.saveState(journal.state)
	}
	return nil
}

func (journal *Journal) pendingLocked() ([]JournalItem, error) {
	directory := filepath.Join(journal.root, "pending")
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(left, right int) bool { return entries[left].Name() < entries[right].Name() })
	result := make([]JournalItem, 0, len(entries))
	for _, entry := range entries {
		matches := recordFilenamePattern.FindStringSubmatch(entry.Name())
		if len(matches) != 3 || entry.Type()&os.ModeSymlink != 0 {
			return nil, errors.New("journal pending directory contains an unknown entry")
		}
		path := filepath.Join(directory, entry.Name())
		info, err := os.Lstat(path)
		if err != nil || !privateRegularFile(info) {
			return nil, errors.New("journal record is not a private owned regular file")
		}
		file, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW, 0)
		if err != nil {
			return nil, errors.New("open journal record without following links")
		}
		openedInfo, statErr := file.Stat()
		if statErr != nil || !privateRegularFile(openedInfo) {
			file.Close()
			return nil, errors.New("opened journal record is not a private owned regular file")
		}
		content, readErr := io.ReadAll(io.LimitReader(file, MaximumAlertSize+(64<<10)+1))
		closeErr := file.Close()
		if readErr != nil || closeErr != nil || len(content) == 0 || len(content) > MaximumAlertSize+(64<<10) {
			return nil, errors.New("journal record is unreadable or oversized")
		}
		var record Record
		decoder := json.NewDecoder(bytes.NewReader(content))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&record); err != nil || ensureEOF(decoder) != nil || record.Validate() != nil {
			return nil, errors.New("journal record is invalid")
		}
		sequence, err := strconv.ParseUint(matches[1], 10, 64)
		if err != nil || sequence != record.Sequence || matches[2] != record.EntryHash || entry.Name() != journalRecordName(record) {
			return nil, errors.New("journal record filename is inconsistent")
		}
		result = append(result, JournalItem{Path: path, Record: record, Body: content})
	}
	return result, nil
}

func journalRecordName(record Record) string {
	return fmt.Sprintf("%020d-%s.json", record.Sequence, record.EntryHash)
}

func createPrivateImmutable(path string, content []byte) error {
	directory := filepath.Dir(path)
	stagingDirectory := filepath.Dir(directory)
	random := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, random); err != nil {
		return err
	}
	temporary := filepath.Join(stagingDirectory, ".record."+hex.EncodeToString(random)+".tmp")
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(temporary)
		}
	}()
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
	if err := os.Link(temporary, path); err != nil {
		return fmt.Errorf("publish immutable journal record: %w", err)
	}
	if err := syncDirectory(directory); err != nil {
		return err
	}
	if err := os.Remove(temporary); err != nil {
		return err
	}
	cleanup = false
	return syncDirectory(stagingDirectory)
}

func requirePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || !ownedByCurrentUser(info) {
		return errors.New("journal directory must be private, owned, and not a symlink")
	}
	return nil
}

func ownedByCurrentUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}

func privateRegularFile(info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm() == 0o600 && ownedByCurrentUser(info)
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func journalStatePath(root string) string {
	return filepath.Join(root, "state.json")
}
