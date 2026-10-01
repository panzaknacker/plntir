package filecrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	KeyBytes         = 32
	NoncePrefixBytes = 4
	NonceBytes       = 12
	TagBytes         = 16
	MediaPartBytes   = 64 << 20
)

type FileCipher struct {
	aead        cipher.AEAD
	noncePrefix [NoncePrefixBytes]byte
}

type Chunk struct {
	Index      uint64
	Nonce      [NonceBytes]byte
	Ciphertext []byte
}

func GenerateKey(source io.Reader) ([]byte, error) {
	if source == nil {
		source = rand.Reader
	}
	key := make([]byte, KeyBytes)
	if _, err := io.ReadFull(source, key); err != nil {
		return nil, fmt.Errorf("generate file key: %w", err)
	}
	return key, nil
}

func New(key []byte, nonceSource io.Reader) (*FileCipher, error) {
	if len(key) != KeyBytes {
		return nil, fmt.Errorf("file key must be %d bytes", KeyBytes)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if nonceSource == nil {
		nonceSource = rand.Reader
	}
	result := &FileCipher{aead: aead}
	if _, err := io.ReadFull(nonceSource, result.noncePrefix[:]); err != nil {
		return nil, fmt.Errorf("generate nonce prefix: %w", err)
	}
	return result, nil
}

func Restore(key []byte, prefix [NoncePrefixBytes]byte) (*FileCipher, error) {
	return New(key, bytesReader(prefix[:]))
}

func (f *FileCipher) NoncePrefix() [NoncePrefixBytes]byte {
	return f.noncePrefix
}

func (f *FileCipher) Seal(index uint64, plaintext, aad []byte) Chunk {
	nonce := f.nonce(index)
	return Chunk{
		Index:      index,
		Nonce:      nonce,
		Ciphertext: f.aead.Seal(nil, nonce[:], plaintext, aad),
	}
}

func (f *FileCipher) Open(chunk Chunk, aad []byte) ([]byte, error) {
	want := f.nonce(chunk.Index)
	if chunk.Nonce != want {
		return nil, errors.New("chunk nonce does not match file prefix and index")
	}
	plaintext, err := f.aead.Open(nil, chunk.Nonce[:], chunk.Ciphertext, aad)
	if err != nil {
		return nil, errors.New("chunk authentication failed")
	}
	return plaintext, nil
}

func (f *FileCipher) nonce(index uint64) [NonceBytes]byte {
	var nonce [NonceBytes]byte
	copy(nonce[:NoncePrefixBytes], f.noncePrefix[:])
	binary.BigEndian.PutUint64(nonce[NoncePrefixBytes:], index)
	return nonce
}

type fixedReader struct {
	data []byte
	off  int
}

func bytesReader(data []byte) io.Reader {
	copyOfData := append([]byte(nil), data...)
	return &fixedReader{data: copyOfData}
}

func (r *fixedReader) Read(target []byte) (int, error) {
	if r.off == len(r.data) {
		return 0, io.EOF
	}
	n := copy(target, r.data[r.off:])
	r.off += n
	return n, nil
}
