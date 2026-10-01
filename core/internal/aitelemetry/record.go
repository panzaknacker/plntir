package aitelemetry

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"plntir/core/internal/filecrypto"
)

const (
	SchemaVersion       = 1
	ChunkBytes          = 1 << 20
	MaximumSegmentBytes = 64 << 20
	maximumMessages     = 100_000
)

var (
	sealedMagic = [12]byte{'P', 'L', 'N', 'T', 'I', 'R', '-', 'A', 'I', '-', '1', 0}
	opaqueID    = regexp.MustCompile(`^[a-z][a-z0-9]{0,15}_[0-9a-hjkmnp-tv-z]{32}$`)
	hexSHA256   = regexp.MustCompile(`^[a-f0-9]{64}$`)
	safeLabel   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._:+/@()-]{0,255}$`)
)

type Record struct {
	SchemaVersion         int       `json:"schema_version"`
	CaptureID             string    `json:"capture_id"`
	Source                string    `json:"source"`
	Coverage              string    `json:"coverage"`
	App                   string    `json:"app"`
	Model                 string    `json:"model,omitempty"`
	SegmentIndex          uint32    `json:"segment_index"`
	FinalSegment          bool      `json:"final_segment"`
	PreviousSegmentSHA256 string    `json:"previous_segment_sha256,omitempty"`
	StartedAt             string    `json:"started_at"`
	EndedAt               string    `json:"ended_at"`
	Messages              []Message `json:"messages"`
}

type Message struct {
	Sequence         uint64       `json:"sequence"`
	Role             string       `json:"role"`
	OccurredAt       string       `json:"occurred_at"`
	ContentAvailable bool         `json:"content_available"`
	Content          string       `json:"content,omitempty"`
	ToolCalls        []ToolCall   `json:"tool_calls,omitempty"`
	Attachments      []Attachment `json:"attachments,omitempty"`
}

type ToolCall struct {
	InvocationID    string          `json:"invocation_id"`
	Name            string          `json:"name"`
	Arguments       json.RawMessage `json:"arguments"`
	Status          string          `json:"status"`
	OutputAvailable bool            `json:"output_available"`
	Output          string          `json:"output,omitempty"`
}

// Attachment deliberately has no binary-data member. presence means that the
// attachment was actually sent to the AI source; only its extracted text and
// integrity metadata may be captured.
type Attachment struct {
	Name          string `json:"name"`
	MIMEType      string `json:"mime_type"`
	SizeBytes     int64  `json:"size_bytes"`
	SHA256        string `json:"sha256"`
	ExtractedText string `json:"extracted_text"`
}

type Binding struct {
	AccountID string
	DeviceID  string
	CaptureID string
}

type SealedRecord struct {
	Bytes           []byte
	NoncePrefix     [filecrypto.NoncePrefixBytes]byte
	PlaintextSHA256 [sha256.Size]byte
}

func Marshal(record Record) ([]byte, error) {
	if err := Validate(record); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	if len(encoded) > MaximumSegmentBytes {
		return nil, errors.New("AI record segment exceeds 64 MiB; create a chained segment without truncating content")
	}
	return encoded, nil
}

func Unmarshal(encoded []byte) (Record, error) {
	if len(encoded) == 0 || len(encoded) > MaximumSegmentBytes {
		return Record{}, errors.New("AI record encoding is empty or oversized")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var record Record
	if err := decoder.Decode(&record); err != nil {
		return Record{}, errors.New("AI record encoding is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Record{}, errors.New("AI record has trailing data")
	}
	canonical, err := Marshal(record)
	if err != nil {
		return Record{}, err
	}
	if !bytes.Equal(canonical, encoded) {
		return Record{}, errors.New("AI record is not canonical JSON")
	}
	return record, nil
}

func Validate(record Record) error {
	if record.SchemaVersion != SchemaVersion || !opaqueID.MatchString(record.CaptureID) ||
		!strings.HasPrefix(record.CaptureID, "cap_") || !validSource(record.Source) || !validCoverage(record.Coverage) ||
		!safeLabel.MatchString(record.App) || (record.Model != "" && !safeLabel.MatchString(record.Model)) ||
		len(record.Messages) == 0 || len(record.Messages) > maximumMessages {
		return errors.New("AI record identity or source metadata is invalid")
	}
	if record.SegmentIndex == 0 {
		if record.PreviousSegmentSHA256 != "" {
			return errors.New("first AI segment cannot have a predecessor")
		}
	} else if !hexSHA256.MatchString(record.PreviousSegmentSHA256) {
		return errors.New("continued AI segment must bind its predecessor")
	}
	startedAt, err := time.Parse(time.RFC3339Nano, record.StartedAt)
	if err != nil || startedAt.Year() < 2020 {
		return errors.New("AI record start time is invalid")
	}
	endedAt, err := time.Parse(time.RFC3339Nano, record.EndedAt)
	if err != nil || endedAt.Before(startedAt) || endedAt.Sub(startedAt) > 366*24*time.Hour {
		return errors.New("AI record end time is invalid")
	}
	var prior uint64
	for index, message := range record.Messages {
		if message.Sequence == 0 || (index > 0 && message.Sequence <= prior) || !validRole(message.Role) {
			return errors.New("AI message order or role is invalid")
		}
		prior = message.Sequence
		occurredAt, err := time.Parse(time.RFC3339Nano, message.OccurredAt)
		if err != nil || occurredAt.Before(startedAt.Add(-time.Minute)) || occurredAt.After(endedAt.Add(time.Minute)) {
			return errors.New("AI message time is outside its segment")
		}
		if !message.ContentAvailable && (message.Content != "" || len(message.ToolCalls) != 0 || len(message.Attachments) != 0) {
			return errors.New("unavailable AI content cannot contain captured data")
		}
		if record.Coverage == "full" && !message.ContentAvailable {
			return errors.New("full AI coverage cannot contain unavailable messages")
		}
		if record.Coverage == "content-unavailable" && message.ContentAvailable {
			return errors.New("content-unavailable coverage cannot contain message content")
		}
		for _, call := range message.ToolCalls {
			if !validateToolCall(call) {
				return errors.New("AI tool call is invalid")
			}
		}
		for _, attachment := range message.Attachments {
			if !validateAttachment(attachment) {
				return errors.New("AI attachment text metadata is invalid")
			}
		}
	}
	return nil
}

func Seal(record Record, binding Binding, key []byte, nonceSource io.Reader) (SealedRecord, error) {
	if err := validateBinding(record, binding); err != nil {
		return SealedRecord{}, err
	}
	plaintext, err := Marshal(record)
	if err != nil {
		return SealedRecord{}, err
	}
	cipher, err := filecrypto.New(key, nonceSource)
	if err != nil {
		return SealedRecord{}, err
	}
	hash := sha256.Sum256(plaintext)
	chunkCount := (len(plaintext) + ChunkBytes - 1) / ChunkBytes
	buffer := bytes.NewBuffer(make([]byte, 0, len(plaintext)+chunkCount*filecrypto.TagBytes+64+chunkCount*4))
	prefix := cipher.NoncePrefix()
	buffer.Write(sealedMagic[:])
	buffer.Write(prefix[:])
	_ = binary.Write(buffer, binary.BigEndian, uint64(len(plaintext)))
	buffer.Write(hash[:])
	_ = binary.Write(buffer, binary.BigEndian, uint32(chunkCount))
	for index := 0; index < chunkCount; index++ {
		start := index * ChunkBytes
		end := start + ChunkBytes
		if end > len(plaintext) {
			end = len(plaintext)
		}
		chunk := cipher.Seal(uint64(index), plaintext[start:end], chunkAAD(binding, uint64(index)))
		_ = binary.Write(buffer, binary.BigEndian, uint32(len(chunk.Ciphertext)))
		buffer.Write(chunk.Ciphertext)
	}
	return SealedRecord{Bytes: buffer.Bytes(), NoncePrefix: prefix, PlaintextSHA256: hash}, nil
}

func Open(sealed []byte, binding Binding, key []byte) (Record, error) {
	const headerBytes = 12 + filecrypto.NoncePrefixBytes + 8 + sha256.Size + 4
	if len(sealed) < headerBytes || len(sealed) > MaximumSegmentBytes+4096 {
		return Record{}, errors.New("sealed AI record is empty or oversized")
	}
	reader := bytes.NewReader(sealed)
	var magic [len(sealedMagic)]byte
	if _, err := io.ReadFull(reader, magic[:]); err != nil || magic != sealedMagic {
		return Record{}, errors.New("sealed AI record header is invalid")
	}
	var prefix [filecrypto.NoncePrefixBytes]byte
	if _, err := io.ReadFull(reader, prefix[:]); err != nil {
		return Record{}, errors.New("sealed AI record nonce prefix is missing")
	}
	var plaintextBytes uint64
	if err := binary.Read(reader, binary.BigEndian, &plaintextBytes); err != nil || plaintextBytes == 0 || plaintextBytes > MaximumSegmentBytes {
		return Record{}, errors.New("sealed AI record plaintext length is invalid")
	}
	var expectedHash [sha256.Size]byte
	if _, err := io.ReadFull(reader, expectedHash[:]); err != nil {
		return Record{}, errors.New("sealed AI record hash is missing")
	}
	var chunkCount uint32
	if err := binary.Read(reader, binary.BigEndian, &chunkCount); err != nil || chunkCount == 0 ||
		uint64(chunkCount) != (plaintextBytes+ChunkBytes-1)/ChunkBytes {
		return Record{}, errors.New("sealed AI record chunk count is invalid")
	}
	cipher, err := filecrypto.Restore(key, prefix)
	if err != nil {
		return Record{}, err
	}
	plaintext := bytes.NewBuffer(make([]byte, 0, int(plaintextBytes)))
	for index := uint32(0); index < chunkCount; index++ {
		var ciphertextBytes uint32
		if err := binary.Read(reader, binary.BigEndian, &ciphertextBytes); err != nil {
			return Record{}, errors.New("sealed AI record chunk length is missing")
		}
		remainingPlaintext := plaintextBytes - uint64(plaintext.Len())
		expectedPlaintext := uint64(ChunkBytes)
		if remainingPlaintext < expectedPlaintext {
			expectedPlaintext = remainingPlaintext
		}
		if uint64(ciphertextBytes) != expectedPlaintext+filecrypto.TagBytes || uint64(ciphertextBytes) > uint64(reader.Len()) {
			return Record{}, errors.New("sealed AI record chunk length is invalid")
		}
		ciphertext := make([]byte, ciphertextBytes)
		if _, err := io.ReadFull(reader, ciphertext); err != nil {
			return Record{}, errors.New("sealed AI record chunk is truncated")
		}
		chunk := filecrypto.Chunk{Index: uint64(index), Ciphertext: ciphertext}
		copy(chunk.Nonce[:filecrypto.NoncePrefixBytes], prefix[:])
		binary.BigEndian.PutUint64(chunk.Nonce[filecrypto.NoncePrefixBytes:], uint64(index))
		opened, err := cipher.Open(chunk, chunkAAD(binding, uint64(index)))
		if err != nil {
			return Record{}, err
		}
		plaintext.Write(opened)
	}
	if reader.Len() != 0 || uint64(plaintext.Len()) != plaintextBytes || sha256.Sum256(plaintext.Bytes()) != expectedHash {
		return Record{}, errors.New("sealed AI record length or hash is invalid")
	}
	record, err := Unmarshal(plaintext.Bytes())
	if err != nil {
		return Record{}, err
	}
	if err := validateBinding(record, binding); err != nil {
		return Record{}, err
	}
	return record, nil
}

func validateBinding(record Record, binding Binding) error {
	if !opaqueID.MatchString(binding.AccountID) || !strings.HasPrefix(binding.AccountID, "usr_") ||
		!opaqueID.MatchString(binding.DeviceID) || !strings.HasPrefix(binding.DeviceID, "dev_") ||
		binding.CaptureID != record.CaptureID {
		return errors.New("AI encryption binding is invalid")
	}
	return nil
}

func chunkAAD(binding Binding, index uint64) []byte {
	buffer := bytes.NewBufferString("plntir-ai-record-chunk-v1\x00")
	for _, value := range []string{binding.AccountID, binding.DeviceID, binding.CaptureID} {
		_ = binary.Write(buffer, binary.BigEndian, uint32(len(value)))
		buffer.WriteString(value)
	}
	_ = binary.Write(buffer, binary.BigEndian, index)
	return buffer.Bytes()
}

func validateToolCall(call ToolCall) bool {
	if !opaqueID.MatchString(call.InvocationID) || !strings.HasPrefix(call.InvocationID, "tool_") ||
		!safeLabel.MatchString(call.Name) || (call.Status != "requested" && call.Status != "succeeded" && call.Status != "failed") ||
		len(call.Arguments) == 0 || len(call.Arguments) > 16<<20 || !json.Valid(call.Arguments) {
		return false
	}
	if !call.OutputAvailable && call.Output != "" {
		return false
	}
	return true
}

func validateAttachment(attachment Attachment) bool {
	if attachment.Name == "" || len(attachment.Name) > 1024 || strings.ContainsRune(attachment.Name, 0) ||
		attachment.MIMEType == "" || len(attachment.MIMEType) > 255 || strings.ContainsAny(attachment.MIMEType, "\x00\r\n") ||
		attachment.SizeBytes < 0 || !hexSHA256.MatchString(attachment.SHA256) {
		return false
	}
	decoded, err := hex.DecodeString(attachment.SHA256)
	return err == nil && len(decoded) == sha256.Size
}

func validSource(value string) bool {
	return value == "codex-cli" || value == "claude-code-cli" || value == "safari" ||
		value == "chatgpt-native" || value == "claude-native" || value == "cowork-native"
}

func validCoverage(value string) bool {
	return value == "full" || value == "partial" || value == "content-unavailable"
}

func validRole(value string) bool {
	return value == "system" || value == "user" || value == "assistant" || value == "tool"
}

func SegmentSHA256(encoded []byte) string {
	value := sha256.Sum256(encoded)
	return hex.EncodeToString(value[:])
}

func (record Record) String() string {
	return fmt.Sprintf("AIRecord[%s,%s,%d]", record.CaptureID, record.Coverage, record.SegmentIndex)
}
