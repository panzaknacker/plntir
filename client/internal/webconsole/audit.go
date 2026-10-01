package webconsole

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type AuditLog struct {
	path string
	mu   sync.Mutex
}

type auditRecord struct {
	Timestamp string         `json:"timestamp"`
	Event     string         `json:"event"`
	Username  string         `json:"username,omitempty"`
	RemoteIP  string         `json:"remote_ip"`
	Success   bool           `json:"success"`
	Details   map[string]any `json:"details,omitempty"`
}

func NewAuditLog(path string) (*AuditLog, error) {
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("audit parent must be a non-symlink directory")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("audit parent must not be group or world writable")
	}
	if existing, err := os.Lstat(path); err == nil {
		if !existing.Mode().IsRegular() || existing.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("audit path must be a regular file")
		}
		if existing.Mode().Perm() != 0o600 {
			return nil, errors.New("audit file must have mode 0600")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return &AuditLog{path: path}, nil
}

func (log *AuditLog) Write(event, username, remoteIP string, success bool, details map[string]any) error {
	record := auditRecord{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Event:     event,
		Username:  username,
		RemoteIP:  remoteIP,
		Success:   success,
		Details:   details,
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	log.mu.Lock()
	defer log.mu.Unlock()
	file, err := os.OpenFile(log.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Write(encoded); err != nil {
		return err
	}
	return file.Sync()
}

func (log *AuditLog) Read(limit int) ([]auditRecord, error) {
	if limit < 1 || limit > 2000 {
		return nil, errors.New("audit limit must be between 1 and 2000")
	}
	log.mu.Lock()
	defer log.mu.Unlock()
	file, err := os.Open(log.path)
	if errors.Is(err, os.ErrNotExist) {
		return []auditRecord{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()

	ring := make([]auditRecord, limit)
	count := 0
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 512<<10)
	for scanner.Scan() {
		if len(scanner.Bytes()) == 0 {
			continue
		}
		var record auditRecord
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			return nil, errors.New("dashboard audit log contains invalid JSON")
		}
		if record.Timestamp == "" || record.Event == "" || record.RemoteIP == "" {
			return nil, errors.New("dashboard audit log contains an invalid record")
		}
		ring[count%limit] = record
		count++
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	size := count
	if size > limit {
		size = limit
	}
	result := make([]auditRecord, 0, size)
	for offset := 0; offset < size; offset++ {
		index := (count - 1 - offset) % limit
		result = append(result, ring[index])
	}
	return result, nil
}
