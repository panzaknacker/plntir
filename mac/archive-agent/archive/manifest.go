package archive

import (
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type PlaceholderDetector func(relativePath string, identity FileIdentity) (bool, error)

type PlanOptions struct {
	ChunkBytes               int64
	CreatedAt                time.Time
	Previous                 PreviousSnapshot
	PlaceholderDetector      PlaceholderDetector
	TestOnlyAllowSmallChunks bool
}

func BuildPlan(root string, options PlanOptions) (Plan, error) {
	if options.CreatedAt.IsZero() {
		return Plan{}, errors.New("archive plan creation time is required")
	}
	chunkBytes := options.ChunkBytes
	if chunkBytes == 0 {
		chunkBytes = DefaultPlaintextBytes
	}
	if chunkBytes <= 0 || chunkBytes > MaximumPlaintextBytes {
		return Plan{}, errors.New("archive chunk size is outside the supported range")
	}
	if chunkBytes < MinimumProductionBytes && !options.TestOnlyAllowSmallChunks {
		return Plan{}, errors.New("archive chunks below 5 MiB are test-only")
	}
	rootDirectory, err := openRootNoFollow(root)
	if err != nil {
		return Plan{}, err
	}
	defer rootDirectory.Close()
	rootMetadata, err := statFile(rootDirectory)
	if err != nil || rootMetadata.typeBits != unix.S_IFDIR {
		return Plan{}, errors.New("archive root is not a directory")
	}
	plan := Plan{
		SchemaVersion:      SchemaVersion,
		Root:               root,
		CreatedAt:          options.CreatedAt.UTC(),
		PreviousSnapshotID: options.Previous.SnapshotID,
		PriorKeyEnvelopes:  make(map[string]KeyEnvelopes),
	}
	if options.Previous.SnapshotID != "" && options.Previous.Root != root {
		return Plan{}, errors.New("previous snapshot belongs to a different archive root")
	}
	detector := options.PlaceholderDetector
	if detector == nil {
		detector = defaultPlaceholderDetector
	}
	if err := scanDirectory(rootDirectory, "", rootMetadata.identity.Device, chunkBytes, options.Previous, detector, &plan); err != nil {
		return Plan{}, err
	}
	sortPlan(&plan)
	if err := plan.SealDigest(); err != nil {
		return Plan{}, err
	}
	if err := plan.Validate(); err != nil {
		return Plan{}, fmt.Errorf("validate generated archive plan: %w", err)
	}
	return plan, nil
}

func scanDirectory(directory *os.File, prefix string, rootDevice uint64, chunkBytes int64, previous PreviousSnapshot, detector PlaceholderDetector, plan *Plan) error {
	// recursion stays descriptor-based so a renamed path or symlink swap cannot
	// redirect traversal outside the selected root.
	names, err := directoryNames(directory)
	if err != nil {
		return err
	}
	for _, name := range names {
		relative := name
		if prefix != "" {
			relative = path.Join(prefix, name)
		}
		metadata, statErr := statAtNoFollow(directory, name)
		if statErr != nil {
			return fmt.Errorf("inspect archive path %q: %w", relative, statErr)
		}
		entryType, supported := typeFromBits(metadata.typeBits)
		if metadata.identity.Device != rootDevice {
			plan.Excluded = append(plan.Excluded, ExcludedPath{Path: relative, Reason: "mount_boundary"})
			continue
		}
		if reason := exclusionReason(relative, entryType == EntryDirectory); reason != "" {
			plan.Excluded = append(plan.Excluded, ExcludedPath{Path: relative, Reason: reason})
			continue
		}
		if !supported {
			plan.Excluded = append(plan.Excluded, ExcludedPath{Path: relative, Reason: "unsupported_special_file"})
			continue
		}
		entry := Entry{
			Path:            relative,
			Type:            entryType,
			Mode:            metadata.mode,
			UID:             metadata.uid,
			GID:             metadata.gid,
			ModTimeUnixNano: metadata.identity.ModTimeUnixNano,
			SizeBytes:       metadata.identity.SizeBytes,
			Identity:        metadata.identity,
		}
		switch entryType {
		case EntryDirectory:
			plan.Entries = append(plan.Entries, entry)
			child, openErr := openDirectoryAt(directory, name)
			if openErr != nil {
				return fmt.Errorf("open archive directory %q without symlinks: %w", relative, openErr)
			}
			openedMetadata, openedErr := statFile(child)
			if openedErr != nil || !equalIdentity(openedMetadata.identity, metadata.identity) {
				child.Close()
				return fmt.Errorf("archive directory %q changed during planning", relative)
			}
			recurseErr := scanDirectory(child, relative, rootDevice, chunkBytes, previous, detector, plan)
			child.Close()
			if recurseErr != nil {
				return recurseErr
			}
		case EntrySymlink:
			target, linkErr := readLinkAt(directory, name)
			if linkErr != nil {
				return fmt.Errorf("read archive symlink %q: %w", relative, linkErr)
			}
			entry.LinkTarget = target
			after, statErr := statAtNoFollow(directory, name)
			if statErr != nil || !equalIdentity(after.identity, metadata.identity) {
				return fmt.Errorf("archive symlink %q changed during planning", relative)
			}
			plan.Entries = append(plan.Entries, entry)
		case EntryRegular:
			placeholder, detectErr := detector(relative, metadata.identity)
			if detectErr != nil {
				return fmt.Errorf("qualify iCloud state for %q: %w", relative, detectErr)
			}
			if placeholder {
				plan.Excluded = append(plan.Excluded, ExcludedPath{Path: relative, Reason: "icloud_not_local"})
				continue
			}
			plan.LogicalBytes += entry.SizeBytes
			if old, exists := previous.Entries[relative]; exists && old.Type == EntryRegular && equalIdentity(old.Identity, entry.Identity) && reusableObjects(old.Objects, entry, previous.KeyEnvelopes) {
				entry.Reused = true
				entry.Objects = append([]ObjectRef(nil), old.Objects...)
				for _, object := range entry.Objects {
					plan.PriorKeyEnvelopes[object.ArchiveKeyID] = previous.KeyEnvelopes[object.ArchiveKeyID]
				}
				plan.Entries = append(plan.Entries, entry)
				continue
			}
			plan.Entries = append(plan.Entries, entry)
			for offset := int64(0); offset < entry.SizeBytes; offset += chunkBytes {
				length := min(chunkBytes, entry.SizeBytes-offset)
				plan.Work = append(plan.Work, WorkChunk{
					ID:             makeWorkID(relative, offset, length, entry.Identity),
					Path:           relative,
					Offset:         offset,
					Length:         length,
					Identity:       entry.Identity,
					PlaintextLimit: chunkBytes,
				})
			}
		}
	}
	return nil
}

func reusableObjects(objects []ObjectRef, entry Entry, envelopes map[string]KeyEnvelopes) bool {
	if !objectRefsCover(objects, entry.SizeBytes) {
		return false
	}
	for _, object := range objects {
		if object.WorkID != makeWorkID(entry.Path, object.Offset, object.PlaintextBytes, entry.Identity) {
			return false
		}
		envelope, exists := envelopes[object.ArchiveKeyID]
		if !exists || validateEnvelopes(envelope) != nil {
			return false
		}
	}
	return true
}

func typeFromBits(bits uint32) (EntryType, bool) {
	switch bits {
	case unix.S_IFREG:
		return EntryRegular, true
	case unix.S_IFDIR:
		return EntryDirectory, true
	case unix.S_IFLNK:
		return EntrySymlink, true
	default:
		return "", false
	}
}

func defaultPlaceholderDetector(relative string, _ FileIdentity) (bool, error) {
	return strings.HasSuffix(strings.ToLower(path.Base(relative)), ".icloud"), nil
}

func exclusionReason(relative string, isDirectory bool) string {
	components := strings.Split(relative, "/")
	base := components[len(components)-1]
	if len(components) == 1 {
		switch base {
		case ".Trash", ".Trashes":
			return "trash"
		case ".cache":
			return "cache"
		case ".TemporaryItems", ".tmp", "tmp", "Temp":
			return "temporary"
		}
	}
	if len(components) >= 2 && components[0] == "Library" && components[1] == "Caches" {
		return "cache"
	}
	if isDirectory && len(components) >= 4 && components[0] == "Library" && (components[1] == "Containers" || components[1] == "Group Containers") {
		for index := 2; index < len(components); index++ {
			if components[index] == "Caches" {
				return "cache"
			}
			if components[index] == "tmp" || components[index] == "Temp" {
				return "temporary"
			}
		}
	}
	return ""
}
