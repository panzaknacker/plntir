package archive

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

var recordMagic = [8]byte{'P', 'L', 'N', 'T', 'A', 'R', 'C', 1}

const recordHeaderBytes = 8 + 8 + NonceBytes + 8 + sha256.Size + sha256.Size + 8

func ReadWorkPlaintext(root string, work WorkChunk) ([]byte, error) {
	if work.Offset < 0 || work.Length <= 0 || work.Length > MaximumPlaintextBytes || work.Length > work.PlaintextLimit {
		return nil, errors.New("archive work range is invalid")
	}
	file, before, err := openRegularNoFollow(root, work.Path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if !equalIdentity(before, work.Identity) || work.Offset > before.SizeBytes || work.Length > before.SizeBytes-work.Offset {
		return nil, fmt.Errorf("archive source %q changed after planning", work.Path)
	}
	plaintext := make([]byte, int(work.Length))
	reader := io.NewSectionReader(file, work.Offset, work.Length)
	if _, err := io.ReadFull(reader, plaintext); err != nil {
		Zero(plaintext)
		return nil, fmt.Errorf("read archive work %q: %w", work.ID, err)
	}
	after, err := statFile(file)
	if err != nil {
		Zero(plaintext)
		return nil, err
	}
	if !equalIdentity(before, after.identity) || !equalIdentity(after.identity, work.Identity) {
		Zero(plaintext)
		return nil, fmt.Errorf("archive source %q changed while reading", work.Path)
	}
	return plaintext, nil
}

func EncodeCipherChunk(chunk CipherChunk) ([]byte, error) {
	if chunk.Counter == 0 || chunk.Nonce != nonceFor([NoncePrefixBytes]byte{chunk.Nonce[0], chunk.Nonce[1], chunk.Nonce[2], chunk.Nonce[3]}, chunk.Counter) {
		return nil, errors.New("cipher chunk nonce is invalid")
	}
	if len(chunk.Ciphertext) < GCMTagBytes || len(chunk.Ciphertext) > int(MaximumPlaintextBytes)+GCMTagBytes {
		return nil, errors.New("cipher chunk length is invalid")
	}
	if sha256.Sum256(chunk.Ciphertext) != chunk.CiphertextSHA256 {
		return nil, errors.New("cipher chunk hash is invalid")
	}
	plaintextBytes := len(chunk.Ciphertext) - GCMTagBytes
	var output bytes.Buffer
	output.Grow(recordHeaderBytes + len(chunk.Ciphertext))
	output.Write(recordMagic[:])
	binary.Write(&output, binary.BigEndian, chunk.Counter)
	output.Write(chunk.Nonce[:])
	binary.Write(&output, binary.BigEndian, uint64(plaintextBytes))
	output.Write(chunk.PlaintextSHA256[:])
	output.Write(chunk.CiphertextSHA256[:])
	binary.Write(&output, binary.BigEndian, uint64(len(chunk.Ciphertext)))
	output.Write(chunk.Ciphertext)
	return output.Bytes(), nil
}

func DecodeCipherChunk(record []byte) (CipherChunk, error) {
	if len(record) < recordHeaderBytes+GCMTagBytes || len(record) > recordHeaderBytes+int(MaximumPlaintextBytes)+GCMTagBytes {
		return CipherChunk{}, errors.New("archive object length is invalid")
	}
	reader := bytes.NewReader(record)
	var magic [8]byte
	if _, err := io.ReadFull(reader, magic[:]); err != nil || magic != recordMagic {
		return CipherChunk{}, errors.New("archive object magic is invalid")
	}
	var chunk CipherChunk
	var plaintextBytes uint64
	var ciphertextBytes uint64
	if err := binary.Read(reader, binary.BigEndian, &chunk.Counter); err != nil {
		return CipherChunk{}, err
	}
	if _, err := io.ReadFull(reader, chunk.Nonce[:]); err != nil {
		return CipherChunk{}, err
	}
	if err := binary.Read(reader, binary.BigEndian, &plaintextBytes); err != nil {
		return CipherChunk{}, err
	}
	if _, err := io.ReadFull(reader, chunk.PlaintextSHA256[:]); err != nil {
		return CipherChunk{}, err
	}
	if _, err := io.ReadFull(reader, chunk.CiphertextSHA256[:]); err != nil {
		return CipherChunk{}, err
	}
	if err := binary.Read(reader, binary.BigEndian, &ciphertextBytes); err != nil {
		return CipherChunk{}, err
	}
	if chunk.Counter == 0 || ciphertextBytes != plaintextBytes+GCMTagBytes || ciphertextBytes != uint64(reader.Len()) || plaintextBytes > uint64(MaximumPlaintextBytes) {
		return CipherChunk{}, errors.New("archive object size fields are inconsistent")
	}
	chunk.Ciphertext = make([]byte, int(ciphertextBytes))
	if _, err := io.ReadFull(reader, chunk.Ciphertext); err != nil {
		return CipherChunk{}, err
	}
	if sha256.Sum256(chunk.Ciphertext) != chunk.CiphertextSHA256 {
		return CipherChunk{}, errors.New("archive object ciphertext hash mismatch")
	}
	var prefix [NoncePrefixBytes]byte
	copy(prefix[:], chunk.Nonce[:NoncePrefixBytes])
	if chunk.Nonce != nonceFor(prefix, chunk.Counter) {
		return CipherChunk{}, errors.New("archive object nonce is inconsistent")
	}
	return chunk, nil
}
