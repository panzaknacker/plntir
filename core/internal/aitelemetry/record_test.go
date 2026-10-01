package aitelemetry

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"plntir/core/internal/filecrypto"
)

func completeRecord() Record {
	now := time.Date(2026, 9, 5, 11, 0, 0, 0, time.UTC)
	return Record{
		SchemaVersion: SchemaVersion, CaptureID: "cap_0123456789abcdefghjkmnpqrstvwxyz",
		Source: "codex-cli", Coverage: "full", App: "Codex CLI", Model: "local-observed-model",
		FinalSegment: true, StartedAt: now.Format(time.RFC3339Nano), EndedAt: now.Add(time.Minute).Format(time.RFC3339Nano),
		Messages: []Message{
			{Sequence: 1, Role: "user", OccurredAt: now.Format(time.RFC3339Nano), ContentAvailable: true,
				Content: "Review the attached source", Attachments: []Attachment{{Name: "source.txt", MIMEType: "text/plain",
					SizeBytes: 12, SHA256: strings.Repeat("a", 64), ExtractedText: "actual sent text"}}},
			{Sequence: 2, Role: "assistant", OccurredAt: now.Add(time.Second).Format(time.RFC3339Nano), ContentAvailable: true,
				Content: "I will inspect it", ToolCalls: []ToolCall{{InvocationID: "tool_0123456789abcdefghjkmnpqrstvwxyz",
					Name: "read_file", Arguments: json.RawMessage(`{"path":"source.txt"}`), Status: "succeeded",
					OutputAvailable: true, Output: "actual sent text"}}},
		},
	}
}

func testBinding() Binding {
	return Binding{AccountID: "usr_0123456789abcdefghjkmnpqrstvwxyz", DeviceID: "dev_0123456789abcdefghjkmnpqrstvwxyz",
		CaptureID: "cap_0123456789abcdefghjkmnpqrstvwxyz"}
}

func TestFullRecordRoundTripsAsAuthenticatedChunks(t *testing.T) {
	record := completeRecord()
	key := bytes.Repeat([]byte{0x42}, filecrypto.KeyBytes)
	sealed, err := Seal(record, testBinding(), key, bytes.NewReader([]byte{1, 2, 3, 4}))
	if err != nil {
		t.Fatal(err)
	}
	opened, err := Open(sealed.Bytes, testBinding(), key)
	if err != nil {
		t.Fatal(err)
	}
	if opened.Messages[0].Attachments[0].ExtractedText != "actual sent text" || opened.Messages[1].ToolCalls[0].Output != "actual sent text" {
		t.Fatal("complete supported context did not survive encryption")
	}
	sealed.Bytes[len(sealed.Bytes)-1] ^= 1
	if _, err := Open(sealed.Bytes, testBinding(), key); err == nil {
		t.Fatal("tampered AI ciphertext authenticated")
	}
}

func TestBindingPreventsCrossDeviceReplay(t *testing.T) {
	key := bytes.Repeat([]byte{0x24}, filecrypto.KeyBytes)
	sealed, err := Seal(completeRecord(), testBinding(), key, bytes.NewReader([]byte{4, 3, 2, 1}))
	if err != nil {
		t.Fatal(err)
	}
	wrong := testBinding()
	wrong.DeviceID = "dev_1123456789abcdefghjkmnpqrstvwxyz"
	if _, err := Open(sealed.Bytes, wrong, key); err == nil {
		t.Fatal("AI record replayed under another device binding")
	}
}

func TestSchemaCannotCarryBinaryOrInventContentWhenUnavailable(t *testing.T) {
	record := completeRecord()
	record.Coverage = "content-unavailable"
	if _, err := Marshal(record); err == nil {
		t.Fatal("content was accepted under unavailable coverage")
	}
	encoded, err := Marshal(completeRecord())
	if err != nil {
		t.Fatal(err)
	}
	withBinary := bytes.Replace(encoded, []byte(`"extracted_text":"actual sent text"`),
		[]byte(`"extracted_text":"actual sent text","binary":"AAEC"`), 1)
	if _, err := Unmarshal(withBinary); err == nil {
		t.Fatal("binary attachment field was accepted")
	}
}

func TestRecordCannotBeAnEmptyCapture(t *testing.T) {
	record := completeRecord()
	record.Messages = nil
	if _, err := Marshal(record); err == nil {
		t.Fatal("empty AI capture was accepted")
	}
}

func TestSegmentsBindPredecessorWithoutTruncationFlag(t *testing.T) {
	first := completeRecord()
	first.FinalSegment = false
	first.Messages = first.Messages[:1]
	encoded, err := Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	second := completeRecord()
	second.SegmentIndex = 1
	second.PreviousSegmentSHA256 = SegmentSHA256(encoded)
	second.Messages = second.Messages[1:]
	if _, err := Marshal(second); err != nil {
		t.Fatalf("valid continuation rejected: %v", err)
	}
	second.PreviousSegmentSHA256 = ""
	if _, err := Marshal(second); err == nil {
		t.Fatal("unbound continuation segment was accepted")
	}
}
