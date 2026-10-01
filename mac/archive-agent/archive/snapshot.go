package archive

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"time"
)

type SnapshotManifest struct {
	SchemaVersion      int                     `json:"schema_version"`
	SnapshotID         string                  `json:"snapshot_id"`
	DeviceID           string                  `json:"device_id"`
	ArchiveID          string                  `json:"archive_id"`
	ArchiveKeyID       string                  `json:"archive_key_id"`
	PlanDigestSHA256   string                  `json:"plan_digest_sha256"`
	Root               string                  `json:"root"`
	CreatedAt          time.Time               `json:"created_at"`
	PreviousSnapshotID string                  `json:"previous_snapshot_id,omitempty"`
	LogicalBytes       int64                   `json:"logical_bytes"`
	Entries            []Entry                 `json:"entries"`
	Excluded           []ExcludedPath          `json:"excluded,omitempty"`
	KeyEnvelopes       map[string]KeyEnvelopes `json:"key_envelopes"`
}

func MaterializeSnapshot(plan Plan, state ArchiveState, createdAt time.Time) (SnapshotManifest, error) {
	if err := plan.Validate(); err != nil {
		return SnapshotManifest{}, err
	}
	if err := state.Validate(); err != nil {
		return SnapshotManifest{}, err
	}
	if state.Pending != nil || state.PlanDigestSHA256 != plan.DigestSHA256 || state.Root != plan.Root || createdAt.IsZero() {
		return SnapshotManifest{}, errors.New("archive plan and completed state do not match")
	}
	workByPath := make(map[string][]WorkChunk)
	knownWork := make(map[string]struct{}, len(plan.Work))
	for _, work := range plan.Work {
		workByPath[work.Path] = append(workByPath[work.Path], work)
		knownWork[work.ID] = struct{}{}
		if _, exists := state.Confirmed[work.ID]; !exists {
			return SnapshotManifest{}, fmt.Errorf("archive work %q is not confirmed", work.ID)
		}
	}
	for workID := range state.Confirmed {
		if _, exists := knownWork[workID]; !exists {
			return SnapshotManifest{}, fmt.Errorf("confirmed work %q is absent from the plan", workID)
		}
	}
	manifest := SnapshotManifest{
		SchemaVersion:      SchemaVersion,
		DeviceID:           state.DeviceID,
		ArchiveID:          state.ArchiveID,
		ArchiveKeyID:       state.ArchiveKeyID,
		PlanDigestSHA256:   plan.DigestSHA256,
		Root:               plan.Root,
		CreatedAt:          createdAt.UTC(),
		PreviousSnapshotID: plan.PreviousSnapshotID,
		LogicalBytes:       plan.LogicalBytes,
		Entries:            append([]Entry(nil), plan.Entries...),
		Excluded:           append([]ExcludedPath(nil), plan.Excluded...),
		KeyEnvelopes:       copyKeyEnvelopes(plan.PriorKeyEnvelopes),
	}
	if _, collision := manifest.KeyEnvelopes[state.ArchiveKeyID]; collision {
		return SnapshotManifest{}, errors.New("new snapshot DEK collides with a prior archive key ID")
	}
	manifest.KeyEnvelopes[state.ArchiveKeyID] = state.Envelopes
	for index := range manifest.Entries {
		entry := &manifest.Entries[index]
		if entry.Type != EntryRegular || entry.Reused {
			continue
		}
		for _, work := range workByPath[entry.Path] {
			entry.Objects = append(entry.Objects, state.Confirmed[work.ID])
		}
		if !objectRefsCover(entry.Objects, entry.SizeBytes) {
			return SnapshotManifest{}, fmt.Errorf("confirmed objects do not cover %q", entry.Path)
		}
	}
	encoded, err := canonicalSnapshot(manifest)
	if err != nil {
		return SnapshotManifest{}, err
	}
	digest := sha256.Sum256(encoded)
	manifest.SnapshotID = hex.EncodeToString(digest[:])
	if err := manifest.Validate(); err != nil {
		return SnapshotManifest{}, err
	}
	return manifest, nil
}

func (manifest SnapshotManifest) Validate() error {
	if manifest.SchemaVersion != SchemaVersion || !validHexDigest(manifest.SnapshotID) || !validHexDigest(manifest.PlanDigestSHA256) || !validOpaqueID(manifest.DeviceID, 128) || !validOpaqueID(manifest.ArchiveID, 128) || !validOpaqueID(manifest.ArchiveKeyID, 128) {
		return errors.New("snapshot manifest identity is invalid")
	}
	if !path.IsAbs(manifest.Root) || path.Clean(manifest.Root) != manifest.Root || manifest.CreatedAt.IsZero() || manifest.LogicalBytes < 0 {
		return errors.New("snapshot manifest metadata is invalid")
	}
	seen := make(map[string]struct{}, len(manifest.Entries))
	referencedKeys := make(map[string]struct{})
	objectIDs := make(map[string]struct{})
	keyCounters := make(map[string]struct{})
	logicalBytes := int64(0)
	for _, entry := range manifest.Entries {
		if err := validateRelativePath(entry.Path); err != nil {
			return err
		}
		if _, exists := seen[entry.Path]; exists {
			return fmt.Errorf("duplicate snapshot path %q", entry.Path)
		}
		seen[entry.Path] = struct{}{}
		if entry.Type == EntryRegular {
			logicalBytes += entry.SizeBytes
			if !objectRefsCover(entry.Objects, entry.SizeBytes) {
				return fmt.Errorf("snapshot objects do not cover %q", entry.Path)
			}
			for _, object := range entry.Objects {
				if object.DeviceID != manifest.DeviceID || object.WorkID != makeWorkID(entry.Path, object.Offset, object.PlaintextBytes, entry.Identity) {
					return fmt.Errorf("snapshot object %q has the wrong AAD identity", object.ObjectID)
				}
				if _, exists := manifest.KeyEnvelopes[object.ArchiveKeyID]; !exists {
					return fmt.Errorf("snapshot object %q has no recovery envelope", object.ObjectID)
				}
				if _, duplicate := objectIDs[object.ObjectID]; duplicate {
					return fmt.Errorf("snapshot repeats object ID %q", object.ObjectID)
				}
				objectIDs[object.ObjectID] = struct{}{}
				counterKey := fmt.Sprintf("%s:%d", object.ArchiveKeyID, object.NonceCounter)
				if _, duplicate := keyCounters[counterKey]; duplicate {
					return errors.New("snapshot repeats a nonce counter for one archive key")
				}
				keyCounters[counterKey] = struct{}{}
				referencedKeys[object.ArchiveKeyID] = struct{}{}
			}
		} else if len(entry.Objects) != 0 {
			return fmt.Errorf("non-regular snapshot path %q has objects", entry.Path)
		}
	}
	for keyID, envelopes := range manifest.KeyEnvelopes {
		if _, used := referencedKeys[keyID]; !used && keyID != manifest.ArchiveKeyID {
			return fmt.Errorf("snapshot carries unreferenced key envelope %q", keyID)
		}
		if err := validateEnvelopes(envelopes); err != nil {
			return fmt.Errorf("validate snapshot key envelope %q: %w", keyID, err)
		}
	}
	if logicalBytes != manifest.LogicalBytes {
		return errors.New("snapshot logical byte total is inconsistent")
	}
	encoded, err := canonicalSnapshot(manifest)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(encoded)
	if hex.EncodeToString(digest[:]) != manifest.SnapshotID {
		return errors.New("snapshot manifest digest mismatch")
	}
	return nil
}

func (manifest SnapshotManifest) Previous() PreviousSnapshot {
	entries := make(map[string]Entry, len(manifest.Entries))
	for _, entry := range manifest.Entries {
		entry.Objects = append([]ObjectRef(nil), entry.Objects...)
		entries[entry.Path] = entry
	}
	return PreviousSnapshot{SnapshotID: manifest.SnapshotID, Root: manifest.Root, Entries: entries, KeyEnvelopes: copyKeyEnvelopes(manifest.KeyEnvelopes)}
}

func canonicalSnapshot(manifest SnapshotManifest) ([]byte, error) {
	copyOfManifest := manifest
	copyOfManifest.SnapshotID = ""
	copyOfManifest.Entries = append([]Entry(nil), manifest.Entries...)
	copyOfManifest.Excluded = append([]ExcludedPath(nil), manifest.Excluded...)
	sort.Slice(copyOfManifest.Entries, func(i, j int) bool { return copyOfManifest.Entries[i].Path < copyOfManifest.Entries[j].Path })
	sort.Slice(copyOfManifest.Excluded, func(i, j int) bool { return copyOfManifest.Excluded[i].Path < copyOfManifest.Excluded[j].Path })
	return json.Marshal(copyOfManifest)
}

func copyKeyEnvelopes(source map[string]KeyEnvelopes) map[string]KeyEnvelopes {
	result := make(map[string]KeyEnvelopes, len(source)+1)
	for key, value := range source {
		result[key] = value
	}
	return result
}
