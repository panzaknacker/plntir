package filecrypto

import (
	"bytes"
	"testing"
)

func TestChunksUseUniqueDeterministicNoncesAndAuthenticate(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, KeyBytes)
	cipher, err := New(key, bytes.NewReader([]byte{1, 2, 3, 4}))
	if err != nil {
		t.Fatal(err)
	}
	aad := []byte("file_abc:version_1")
	first := cipher.Seal(0, []byte("first"), aad)
	second := cipher.Seal(1, []byte("second"), aad)
	if first.Nonce == second.Nonce {
		t.Fatal("two chunks reused a nonce")
	}
	restored, err := Restore(key, cipher.NoncePrefix())
	if err != nil {
		t.Fatal(err)
	}
	plain, err := restored.Open(second, aad)
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != "second" {
		t.Fatalf("unexpected plaintext %q", plain)
	}

	second.Ciphertext[0] ^= 1
	if _, err := restored.Open(second, aad); err == nil {
		t.Fatal("tampered ciphertext unexpectedly authenticated")
	}
}

func TestChunkRejectsNonceSubstitution(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, KeyBytes)
	cipher, err := New(key, bytes.NewReader([]byte{9, 8, 7, 6}))
	if err != nil {
		t.Fatal(err)
	}
	chunk := cipher.Seal(8, []byte("payload"), nil)
	chunk.Nonce[0] ^= 1
	if _, err := cipher.Open(chunk, nil); err == nil {
		t.Fatal("substituted nonce unexpectedly accepted")
	}
}
