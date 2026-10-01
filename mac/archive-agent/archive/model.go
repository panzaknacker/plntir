package archive

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"
)

const (
	SchemaVersion          = 1
	DefaultPlaintextBytes  = int64(64<<20) - 64<<10
	MinimumProductionBytes = int64(5 << 20)
	MaximumPlaintextBytes  = int64(64 << 20)
)

type EntryType string

const (
	EntryRegular   EntryType = "regular"
	EntryDirectory EntryType = "directory"
	EntrySymlink   EntryType = "symlink"
)

type FileIdentity struct {
	Device          uint64 `json:"device"`
	Inode           uint64 `json:"inode"`
	SizeBytes       int64  `json:"size_bytes"`
	ModTimeUnixNano int64  `json:"mtime_unix_nano"`
	Mode            uint32 `json:"mode"`
}

type ObjectRef struct {
	ObjectID        string `json:"object_id"`
	DeviceID        string `json:"device_id"`
	ArchiveID       string `json:"archive_id"`
	ArchiveKeyID    string `json:"archive_key_id"`
	WorkID          string `json:"work_id"`
	Offset          int64  `json:"offset"`
	PlaintextBytes  int64  `json:"plaintext_bytes"`
	CiphertextBytes int64  `json:"ciphertext_bytes"`
	NonceCounter    uint64 `json:"nonce_counter"`
	CiphertextHash  string `json:"ciphertext_sha256"`
}

type Entry struct {
	Path            string         `json:"path"`
	Type            EntryType      `json:"type"`
	Mode            uint32         `json:"mode"`
	UID             uint32         `json:"uid"`
	GID             uint32         `json:"gid"`
	ModTimeUnixNano int64          `json:"mtime_unix_nano"`
	SizeBytes       int64          `json:"size_bytes"`
	LinkTarget      string         `json:"link_target,omitempty"`
	Identity        FileIdentity   `json:"identity"`
	Reused          bool           `json:"reused"`
	Objects         []ObjectRef    `json:"objects,omitempty"`
	Metadata        map[string]any `json:"metadata,omitempty"`
}

type WorkChunk struct {
	ID             string       `json:"id"`
	Path           string       `json:"path"`
	Offset         int64        `json:"offset"`
	Length         int64        `json:"length"`
	Identity       FileIdentity `json:"identity"`
	PlaintextLimit int64        `json:"plaintext_limit"`
}

type ExcludedPath struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

type Plan struct {
	SchemaVersion      int                     `json:"schema_version"`
	Root               string                  `json:"root"`
	CreatedAt          time.Time               `json:"created_at"`
	PreviousSnapshotID string                  `json:"previous_snapshot_id,omitempty"`
	LogicalBytes       int64                   `json:"logical_bytes"`
	Entries            []Entry                 `json:"entries"`
	Work               []WorkChunk             `json:"work"`
	Excluded           []ExcludedPath          `json:"excluded,omitempty"`
	PriorKeyEnvelopes  map[string]KeyEnvelopes `json:"prior_key_envelopes,omitempty"`
	DigestSHA256       string                  `json:"digest_sha256"`
}

type PreviousSnapshot struct {
	SnapshotID   string
	Root         string
	Entries      map[string]Entry
	KeyEnvelopes map[string]KeyEnvelopes
}

func (p *Plan) SealDigest() error {
	if p == nil {
		return errors.New("plan is nil")
	}
	copyOfPlan := *p
	copyOfPlan.DigestSHA256 = ""
	encoded, err := json.Marshal(copyOfPlan)
	if err != nil {
		return fmt.Errorf("marshal archive plan: %w", err)
	}
	digest := sha256.Sum256(encoded)
	p.DigestSHA256 = hex.EncodeToString(digest[:])
	return nil
}

func (p Plan) Validate() error {
	if p.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported plan schema %d", p.SchemaVersion)
	}
	if !path.IsAbs(p.Root) || path.Clean(p.Root) != p.Root {
		return errors.New("plan root must be a clean absolute path")
	}
	if p.CreatedAt.IsZero() || p.LogicalBytes < 0 || len(p.DigestSHA256) != sha256.Size*2 {
		return errors.New("plan metadata is incomplete")
	}
	paths := make(map[string]Entry, len(p.Entries))
	logicalBytes := int64(0)
	for _, entry := range p.Entries {
		if err := validateRelativePath(entry.Path); err != nil {
			return err
		}
		if _, exists := paths[entry.Path]; exists {
			return fmt.Errorf("duplicate archive path %q", entry.Path)
		}
		paths[entry.Path] = entry
		if entry.Type != EntryRegular && entry.Type != EntryDirectory && entry.Type != EntrySymlink {
			return fmt.Errorf("unsupported entry type %q", entry.Type)
		}
		if entry.SizeBytes < 0 || entry.Identity.SizeBytes < 0 {
			return fmt.Errorf("entry %q has a negative size", entry.Path)
		}
		if entry.Type != EntryRegular && (entry.Reused || len(entry.Objects) != 0) {
			return fmt.Errorf("non-regular entry %q carries content objects", entry.Path)
		}
		if entry.Type == EntryRegular {
			if entry.SizeBytes > p.LogicalBytes-logicalBytes {
				return errors.New("plan logical byte total is inconsistent")
			}
			logicalBytes += entry.SizeBytes
		}
	}
	if logicalBytes != p.LogicalBytes {
		return errors.New("plan logical byte total is inconsistent")
	}
	excluded := make(map[string]struct{}, len(p.Excluded))
	for _, item := range p.Excluded {
		if err := validateRelativePath(item.Path); err != nil {
			return err
		}
		if item.Reason == "" {
			return fmt.Errorf("excluded path %q has no reason", item.Path)
		}
		if _, exists := excluded[item.Path]; exists {
			return fmt.Errorf("duplicate excluded path %q", item.Path)
		}
		if _, exists := paths[item.Path]; exists {
			return fmt.Errorf("path %q is both archived and excluded", item.Path)
		}
		excluded[item.Path] = struct{}{}
	}
	for keyID, envelopes := range p.PriorKeyEnvelopes {
		if !validOpaqueID(keyID, 128) {
			return errors.New("plan contains an invalid prior archive key ID")
		}
		if err := validateEnvelopes(envelopes); err != nil {
			return fmt.Errorf("validate prior archive key %q: %w", keyID, err)
		}
	}
	workIDs := make(map[string]struct{}, len(p.Work))
	workByPath := make(map[string][]WorkChunk)
	referencedPriorKeys := make(map[string]struct{})
	objectIDs := make(map[string]struct{})
	keyCounters := make(map[string]struct{})
	for _, work := range p.Work {
		if len(work.ID) != sha256.Size*2 {
			return errors.New("work ID is not a SHA-256 digest")
		}
		if _, exists := workIDs[work.ID]; exists {
			return errors.New("duplicate work ID")
		}
		workIDs[work.ID] = struct{}{}
		entry, exists := paths[work.Path]
		if !exists {
			return errors.New("work references an unknown path")
		}
		if entry.Type != EntryRegular || entry.Reused || !equalIdentity(entry.Identity, work.Identity) {
			return fmt.Errorf("work %q does not match its regular entry", work.ID)
		}
		if work.Offset < 0 || work.Length <= 0 || work.PlaintextLimit <= 0 || work.PlaintextLimit > MaximumPlaintextBytes || work.Length > work.PlaintextLimit {
			return errors.New("work range is invalid")
		}
		if makeWorkID(work.Path, work.Offset, work.Length, work.Identity) != work.ID {
			return fmt.Errorf("work ID for %q does not match its content", work.Path)
		}
		workByPath[work.Path] = append(workByPath[work.Path], work)
	}
	for _, entry := range p.Entries {
		if entry.Type != EntryRegular {
			continue
		}
		if entry.Reused {
			if len(workByPath[entry.Path]) != 0 || !objectRefsCover(entry.Objects, entry.SizeBytes) {
				return fmt.Errorf("reused entry %q has incomplete object coverage", entry.Path)
			}
			for _, object := range entry.Objects {
				if object.WorkID != makeWorkID(entry.Path, object.Offset, object.PlaintextBytes, entry.Identity) {
					return fmt.Errorf("reused object %q has the wrong work identity", object.ObjectID)
				}
				if _, exists := p.PriorKeyEnvelopes[object.ArchiveKeyID]; !exists {
					return fmt.Errorf("reused object %q has no prior key envelope", object.ObjectID)
				}
				if _, duplicate := objectIDs[object.ObjectID]; duplicate {
					return fmt.Errorf("archive object ID %q is reused", object.ObjectID)
				}
				objectIDs[object.ObjectID] = struct{}{}
				counterKey := fmt.Sprintf("%s:%d", object.ArchiveKeyID, object.NonceCounter)
				if _, duplicate := keyCounters[counterKey]; duplicate {
					return errors.New("archive plan repeats a nonce counter for one key")
				}
				keyCounters[counterKey] = struct{}{}
				referencedPriorKeys[object.ArchiveKeyID] = struct{}{}
			}
			continue
		}
		if len(entry.Objects) != 0 || !workCovers(workByPath[entry.Path], entry.SizeBytes) {
			return fmt.Errorf("entry %q has incomplete work coverage", entry.Path)
		}
	}
	for keyID := range p.PriorKeyEnvelopes {
		if _, used := referencedPriorKeys[keyID]; !used {
			return fmt.Errorf("plan carries unreferenced prior key envelope %q", keyID)
		}
	}
	copyOfPlan := p
	want := p.DigestSHA256
	copyOfPlan.DigestSHA256 = ""
	encoded, err := json.Marshal(copyOfPlan)
	if err != nil {
		return err
	}
	got := sha256.Sum256(encoded)
	if hex.EncodeToString(got[:]) != want {
		return errors.New("archive plan digest mismatch")
	}
	return nil
}

func sortPlan(plan *Plan) {
	sort.Slice(plan.Entries, func(i, j int) bool { return plan.Entries[i].Path < plan.Entries[j].Path })
	sort.Slice(plan.Work, func(i, j int) bool {
		if plan.Work[i].Path != plan.Work[j].Path {
			return plan.Work[i].Path < plan.Work[j].Path
		}
		return plan.Work[i].Offset < plan.Work[j].Offset
	})
	sort.Slice(plan.Excluded, func(i, j int) bool { return plan.Excluded[i].Path < plan.Excluded[j].Path })
}

func validateRelativePath(value string) error {
	if value == "" || path.IsAbs(value) || strings.ContainsRune(value, '\x00') {
		return fmt.Errorf("unsafe archive path %q", value)
	}
	clean := path.Clean(value)
	if clean != value || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return fmt.Errorf("unclean archive path %q", value)
	}
	return nil
}

func makeWorkID(pathValue string, offset, length int64, identity FileIdentity) string {
	digest := sha256.New()
	digest.Write([]byte("PLNTIR-MAC-ARCHIVE-WORK-V1\x00"))
	encoded, _ := json.Marshal(struct {
		Path     string       `json:"path"`
		Offset   int64        `json:"offset"`
		Length   int64        `json:"length"`
		Identity FileIdentity `json:"identity"`
	}{pathValue, offset, length, identity})
	digest.Write(encoded)
	return hex.EncodeToString(digest.Sum(nil))
}

func equalIdentity(left, right FileIdentity) bool {
	return left == right
}

func workCovers(work []WorkChunk, size int64) bool {
	if size == 0 {
		return len(work) == 0
	}
	if len(work) == 0 {
		return false
	}
	sort.Slice(work, func(i, j int) bool { return work[i].Offset < work[j].Offset })
	next := int64(0)
	for _, item := range work {
		if item.Offset != next || item.Length <= 0 {
			return false
		}
		next += item.Length
	}
	return next == size
}

func objectRefsCover(objects []ObjectRef, size int64) bool {
	if size == 0 {
		return len(objects) == 0
	}
	if len(objects) == 0 {
		return false
	}
	refs := append([]ObjectRef(nil), objects...)
	sort.Slice(refs, func(i, j int) bool { return refs[i].Offset < refs[j].Offset })
	next := int64(0)
	for _, object := range refs {
		if !validOpaqueID(object.ObjectID, 128) || !validOpaqueID(object.DeviceID, 128) || !validOpaqueID(object.ArchiveID, 128) || !validOpaqueID(object.ArchiveKeyID, 128) || !validHexDigest(object.WorkID) || object.Offset != next || object.PlaintextBytes <= 0 || object.CiphertextBytes <= object.PlaintextBytes || object.NonceCounter == 0 {
			return false
		}
		if len(object.CiphertextHash) != sha256.Size*2 {
			return false
		}
		if _, err := hex.DecodeString(object.CiphertextHash); err != nil {
			return false
		}
		next += object.PlaintextBytes
	}
	return next == size
}
