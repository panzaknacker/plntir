package idgen

import (
	"bytes"
	"testing"
)

func TestNewFromUsesStableOpaqueEncoding(t *testing.T) {
	got, err := NewFrom("file", bytes.NewReader(make([]byte, 20)))
	if err != nil {
		t.Fatal(err)
	}
	if got != "file_00000000000000000000000000000000" {
		t.Fatalf("unexpected id %q", got)
	}
	if _, err := NewFrom("Bad-Prefix", bytes.NewReader(make([]byte, 20))); err == nil {
		t.Fatal("invalid prefix unexpectedly accepted")
	}
}
