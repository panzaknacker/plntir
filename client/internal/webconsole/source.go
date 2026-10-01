package webconsole

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"plntir/client/internal/status"
)

var (
	captureNamePattern   = regexp.MustCompile(`^([0-9]{8}T[0-9]{6}Z)-(posture|telemetry)[.]txt[.]gz$`)
	dateDirectoryPattern = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
	archiveNamePattern   = regexp.MustCompile(`^[A-Za-z0-9._-]+[.](tar[.]gz|tar[.]zst[.]gpg)([.]json)?$`)
)

const maxFilePreviewBytes = 512 << 10

type CommandSource struct {
	config Config
}

type DirectoryEntry struct {
	Name       string `json:"name"`
	Path       string `json:"path"`
	Type       string `json:"type"`
	Bytes      int64  `json:"bytes"`
	ModifiedAt string `json:"modified_at"`
	Mode       string `json:"mode"`
	Hidden     bool   `json:"hidden"`
	Readable   bool   `json:"readable"`
}

type DirectoryListing struct {
	SchemaVersion int              `json:"schema_version"`
	OK            bool             `json:"ok"`
	Path          string           `json:"path"`
	Parent        string           `json:"parent"`
	Entries       []DirectoryEntry `json:"entries"`
	EntryCount    int              `json:"entry_count"`
	Unreadable    int              `json:"unreadable"`
	Truncated     bool             `json:"truncated"`
}

type ProbeResult struct {
	OK          bool   `json:"ok"`
	Path        string `json:"path"`
	Files       int    `json:"files"`
	Directories int    `json:"directories"`
	Bytes       int64  `json:"bytes"`
	Unreadable  int    `json:"unreadable"`
}

type FilePreview struct {
	SchemaVersion int    `json:"schema_version"`
	OK            bool   `json:"ok"`
	Path          string `json:"path"`
	Bytes         int64  `json:"bytes"`
	ReturnedBytes int    `json:"returned_bytes"`
	Truncated     bool   `json:"truncated"`
	Kind          string `json:"kind"`
	MIME          string `json:"mime"`
	Text          string `json:"text"`
	HexPreview    string `json:"hex_preview"`
}

type SafariVisit struct {
	VisitedAt      string `json:"visited_at"`
	Domain         string `json:"domain"`
	URL            string `json:"url"`
	Title          string `json:"title"`
	LoadSuccessful *bool  `json:"load_successful"`
	HTTPNonGet     *bool  `json:"http_non_get"`
}

type SafariHistory struct {
	SchemaVersion int           `json:"schema_version"`
	OK            bool          `json:"ok"`
	Source        string        `json:"source"`
	Hours         int           `json:"hours"`
	Limit         int           `json:"limit"`
	Returned      int           `json:"returned"`
	Truncated     bool          `json:"truncated"`
	CapturedAt    string        `json:"captured_at"`
	Visits        []SafariVisit `json:"visits"`
}

type ExportResult struct {
	OK           bool   `json:"ok"`
	Source       string `json:"source"`
	Archive      string `json:"archive"`
	ArchiveBytes int64  `json:"archive_bytes"`
	SHA256       string `json:"sha256,omitempty"`
}

type TelemetryCapture struct {
	ID         string `json:"id"`
	Kind       string `json:"kind"`
	CapturedAt string `json:"captured_at"`
	Bytes      int64  `json:"bytes"`
}

type TelemetryDocument struct {
	ID         string `json:"id"`
	Kind       string `json:"kind"`
	CapturedAt string `json:"captured_at"`
	Text       string `json:"text"`
	Truncated  bool   `json:"truncated"`
}

type Archive struct {
	Name       string `json:"name"`
	Bytes      int64  `json:"bytes"`
	ModifiedAt string `json:"modified_at"`
	Manifest   bool   `json:"manifest"`
}

func NewCommandSource(config Config) *CommandSource {
	return &CommandSource{config: config}
}

func (s *CommandSource) Status(ctx context.Context) (status.Snapshot, error) {
	output, err := s.run(ctx, 30*time.Second, s.config.StatusCommand, nil)
	if err != nil {
		return status.Snapshot{}, err
	}
	var snapshot status.Snapshot
	if err := json.Unmarshal(output, &snapshot); err != nil {
		return status.Snapshot{}, fmt.Errorf("decode status: %w", err)
	}
	if err := snapshot.Validate(); err != nil {
		return status.Snapshot{}, err
	}
	snapshot.Connection.Target = "local-mesh-control-node"
	return snapshot, nil
}

func (s *CommandSource) List(ctx context.Context, path string) (DirectoryListing, error) {
	clean, token, err := s.pathToken(path)
	if err != nil {
		return DirectoryListing{}, err
	}
	output, err := s.action(ctx, 90*time.Second, "list-b64", token)
	if err != nil {
		return DirectoryListing{}, err
	}
	var listing DirectoryListing
	if err := json.Unmarshal(output, &listing); err != nil {
		return DirectoryListing{}, fmt.Errorf("decode directory listing: %w", err)
	}
	if listing.SchemaVersion != 1 || listing.Path != clean || listing.EntryCount != len(listing.Entries) {
		return DirectoryListing{}, errors.New("invalid directory listing response")
	}
	for _, entry := range listing.Entries {
		if _, _, err := s.pathToken(entry.Path); err != nil {
			return DirectoryListing{}, errors.New("directory listing escaped managed home")
		}
	}
	return listing, nil
}

func (s *CommandSource) Probe(ctx context.Context, path string) (ProbeResult, error) {
	clean, token, err := s.pathToken(path)
	if err != nil {
		return ProbeResult{}, err
	}
	output, err := s.action(ctx, 30*time.Minute, "probe-b64", token)
	if err != nil {
		return ProbeResult{}, err
	}
	var result ProbeResult
	if err := json.Unmarshal(output, &result); err != nil {
		return ProbeResult{}, fmt.Errorf("decode probe: %w", err)
	}
	if result.Path != clean || result.Files < 0 || result.Directories < 0 || result.Bytes < 0 || result.Unreadable < 0 {
		return ProbeResult{}, errors.New("invalid probe response")
	}
	return result, nil
}

func (s *CommandSource) Preview(ctx context.Context, path string) (FilePreview, error) {
	clean, token, err := s.pathToken(path)
	if err != nil {
		return FilePreview{}, err
	}
	output, err := s.action(ctx, 90*time.Second, "preview-b64", token)
	if err != nil {
		return FilePreview{}, err
	}
	var preview FilePreview
	if err := json.Unmarshal(output, &preview); err != nil {
		return FilePreview{}, fmt.Errorf("decode file preview: %w", err)
	}
	if preview.SchemaVersion != 1 || !preview.OK || preview.Path != clean ||
		preview.Bytes < 0 || preview.ReturnedBytes < 0 || preview.ReturnedBytes > maxFilePreviewBytes ||
		len(preview.MIME) > 255 {
		return FilePreview{}, errors.New("invalid file preview response")
	}
	switch preview.Kind {
	case "text":
		if len(preview.Text) != preview.ReturnedBytes || preview.HexPreview != "" {
			return FilePreview{}, errors.New("invalid text preview response")
		}
	case "binary":
		decoded, err := hex.DecodeString(preview.HexPreview)
		if err != nil || len(decoded) > 256 || preview.Text != "" {
			return FilePreview{}, errors.New("invalid binary preview response")
		}
	default:
		return FilePreview{}, errors.New("invalid file preview kind")
	}
	return preview, nil
}

func (s *CommandSource) Export(ctx context.Context, path string) (ExportResult, error) {
	clean, token, err := s.pathToken(path)
	if err != nil {
		return ExportResult{}, err
	}
	output, err := s.action(ctx, 12*time.Hour, "export-b64", token)
	if err != nil {
		return ExportResult{}, err
	}
	var result ExportResult
	if err := json.Unmarshal(output, &result); err != nil {
		return ExportResult{}, fmt.Errorf("decode export result: %w", err)
	}
	if !result.OK || result.Source != clean || result.Archive == "" || result.ArchiveBytes <= 0 {
		return ExportResult{}, errors.New("invalid export response")
	}
	return result, nil
}

func (s *CommandSource) Safari(ctx context.Context, hours, limit int) (SafariHistory, error) {
	if hours < 1 || hours > 8760 || limit < 1 || limit > 5000 {
		return SafariHistory{}, errors.New("invalid Safari history range")
	}
	output, err := s.action(
		ctx,
		5*time.Minute,
		"safari-history",
		strconv.Itoa(hours),
		strconv.Itoa(limit),
	)
	if err != nil {
		return SafariHistory{}, err
	}
	var history SafariHistory
	if err := json.Unmarshal(output, &history); err != nil {
		return SafariHistory{}, fmt.Errorf("decode Safari history: %w", err)
	}
	if history.SchemaVersion != 1 || !history.OK || history.Hours != hours || history.Limit != limit || history.Returned != len(history.Visits) {
		return SafariHistory{}, errors.New("invalid Safari history response")
	}
	return history, nil
}

func (s *CommandSource) Refresh(ctx context.Context) (json.RawMessage, error) {
	output, err := s.action(ctx, 3*time.Minute, "refresh")
	if err != nil {
		return nil, err
	}
	if !json.Valid(output) {
		return nil, errors.New("invalid refresh response")
	}
	return json.RawMessage(output), nil
}

func (s *CommandSource) HealthHistory(limit int) ([]json.RawMessage, error) {
	if limit < 1 || limit > 2000 {
		return nil, errors.New("invalid health history limit")
	}
	path := filepath.Join(s.config.MonitorRoot, "mac-health.jsonl")
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	ring := make([]json.RawMessage, limit)
	count := 0
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64<<10), 2<<20)
	for scanner.Scan() {
		line := append([]byte(nil), scanner.Bytes()...)
		if !json.Valid(line) {
			continue
		}
		ring[count%limit] = line
		count++
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	available := count
	if available > limit {
		available = limit
	}
	result := make([]json.RawMessage, 0, available)
	start := count - available
	for index := start; index < count; index++ {
		result = append(result, ring[index%limit])
	}
	return result, nil
}

func (s *CommandSource) TelemetryIndex() ([]TelemetryCapture, error) {
	root := filepath.Join(s.config.MonitorRoot, "security")
	var captures []TelemetryCapture
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			if path == root {
				return nil
			}
			if !dateDirectoryPattern.MatchString(entry.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		matches := captureNamePattern.FindStringSubmatch(entry.Name())
		if matches == nil {
			return nil
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		captures = append(captures, TelemetryCapture{
			ID:         filepath.ToSlash(relative),
			Kind:       matches[2],
			CapturedAt: matches[1],
			Bytes:      info.Size(),
		})
		return nil
	})
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	sort.Slice(captures, func(left, right int) bool {
		return captures[left].CapturedAt > captures[right].CapturedAt
	})
	if len(captures) > 500 {
		captures = captures[:500]
	}
	return captures, nil
}

func (s *CommandSource) ReadTelemetry(id string) (TelemetryDocument, error) {
	path, matches, err := s.resolveCapture(id)
	if err != nil {
		return TelemetryDocument{}, err
	}
	file, err := os.Open(path)
	if err != nil {
		return TelemetryDocument{}, err
	}
	defer file.Close()
	reader, err := gzip.NewReader(file)
	if err != nil {
		return TelemetryDocument{}, err
	}
	defer reader.Close()
	contents, truncated, err := readLimited(reader, s.config.MaxResponseBytes)
	if err != nil {
		return TelemetryDocument{}, err
	}
	return TelemetryDocument{
		ID:         id,
		Kind:       matches[2],
		CapturedAt: matches[1],
		Text:       string(contents),
		Truncated:  truncated,
	}, nil
}

func (s *CommandSource) Archives() ([]Archive, error) {
	var archives []Archive
	err := filepath.WalkDir(s.config.RetrievedRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		if !archiveNamePattern.MatchString(entry.Name()) {
			return nil
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return err
		}
		relative, err := filepath.Rel(s.config.RetrievedRoot, path)
		if err != nil {
			return err
		}
		archives = append(archives, Archive{
			Name:       filepath.ToSlash(relative),
			Bytes:      info.Size(),
			ModifiedAt: info.ModTime().UTC().Format(time.RFC3339),
			Manifest:   strings.HasSuffix(entry.Name(), ".json"),
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(archives, func(left, right int) bool {
		return archives[left].ModifiedAt > archives[right].ModifiedAt
	})
	if len(archives) > 1000 {
		archives = archives[:1000]
	}
	return archives, nil
}

func (s *CommandSource) OpenArchive(name string) (*os.File, os.FileInfo, error) {
	if name == "" || filepath.IsAbs(name) || strings.ContainsRune(name, '\x00') {
		return nil, nil, errors.New("invalid archive name")
	}
	clean := filepath.Clean(filepath.FromSlash(name))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || !archiveNamePattern.MatchString(filepath.Base(clean)) {
		return nil, nil, errors.New("invalid archive name")
	}
	path := filepath.Join(s.config.RetrievedRoot, clean)
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, nil, err
	}
	rootResolved, err := filepath.EvalSymlinks(s.config.RetrievedRoot)
	if err != nil {
		return nil, nil, err
	}
	relative, err := filepath.Rel(rootResolved, resolved)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, nil, errors.New("archive escaped retrieval root")
	}
	file, err := os.Open(resolved)
	if err != nil {
		return nil, nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		file.Close()
		if err == nil {
			err = errors.New("archive is not a regular file")
		}
		return nil, nil, err
	}
	return file, info, nil
}

func (s *CommandSource) action(ctx context.Context, timeout time.Duration, arguments ...string) ([]byte, error) {
	return s.run(ctx, timeout, s.config.ActionCommand, arguments)
}

func (s *CommandSource) run(ctx context.Context, timeout time.Duration, command, arguments []string) ([]byte, error) {
	commandContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	stdout := &limitedBuffer{limit: s.config.MaxResponseBytes}
	stderr := &limitedBuffer{limit: 64 << 10}
	allArguments := append(append([]string(nil), command[1:]...), arguments...)
	process := exec.CommandContext(commandContext, command[0], allArguments...)
	process.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	process.Cancel = func() error {
		if process.Process == nil {
			return os.ErrProcessDone
		}
		err := syscall.Kill(-process.Process.Pid, syscall.SIGTERM)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	process.WaitDelay = 5 * time.Second
	process.Stdin = nil
	process.Stdout = stdout
	process.Stderr = stderr
	if err := process.Run(); err != nil {
		if commandContext.Err() != nil {
			if process.Process != nil {
				_ = syscall.Kill(-process.Process.Pid, syscall.SIGKILL)
			}
			if errors.Is(commandContext.Err(), context.Canceled) {
				return nil, context.Canceled
			}
			return nil, fmt.Errorf("command timed out after %s", timeout)
		}
		message := strings.Join(strings.Fields(stderr.String()), " ")
		if len(message) > 500 {
			message = message[:500]
		}
		if message == "" {
			message = err.Error()
		}
		return nil, errors.New(message)
	}
	if stdout.truncated {
		return nil, errors.New("command response exceeded configured limit")
	}
	return append([]byte(nil), stdout.Bytes()...), nil
}

func (s *CommandSource) pathToken(path string) (string, string, error) {
	if len(path) == 0 || len(path) > 4096 || strings.ContainsRune(path, '\x00') || strings.ContainsAny(path, "\r\n") {
		return "", "", errors.New("invalid managed path")
	}
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		return "", "", errors.New("managed path must be absolute")
	}
	relative, err := filepath.Rel(s.config.ManagedHome, clean)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", "", errors.New("managed path is outside the managed home")
	}
	return clean, base64.StdEncoding.EncodeToString([]byte(clean)), nil
}

func (s *CommandSource) resolveCapture(id string) (string, []string, error) {
	if id == "" || filepath.IsAbs(id) || strings.ContainsRune(id, '\x00') {
		return "", nil, errors.New("invalid capture id")
	}
	clean := filepath.Clean(filepath.FromSlash(id))
	directory := filepath.Dir(clean)
	if filepath.Dir(directory) != "." || !dateDirectoryPattern.MatchString(filepath.Base(directory)) {
		return "", nil, errors.New("invalid capture id")
	}
	matches := captureNamePattern.FindStringSubmatch(filepath.Base(clean))
	if matches == nil {
		return "", nil, errors.New("invalid capture id")
	}
	path := filepath.Join(s.config.MonitorRoot, "security", clean)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		if err == nil {
			err = errors.New("capture is not a regular file")
		}
		return "", nil, err
	}
	return path, matches, nil
}

type limitedBuffer struct {
	bytes.Buffer
	limit     int64
	truncated bool
}

func (buffer *limitedBuffer) Write(value []byte) (int, error) {
	original := len(value)
	remaining := buffer.limit - int64(buffer.Len())
	if remaining <= 0 {
		buffer.truncated = true
		return original, nil
	}
	if int64(len(value)) > remaining {
		value = value[:remaining]
		buffer.truncated = true
	}
	_, _ = buffer.Buffer.Write(value)
	return original, nil
}

func readLimited(reader io.Reader, limit int64) ([]byte, bool, error) {
	limited := io.LimitReader(reader, limit+1)
	contents, err := io.ReadAll(limited)
	if err != nil {
		return nil, false, err
	}
	if int64(len(contents)) > limit {
		return contents[:limit], true, nil
	}
	return contents, false, nil
}
