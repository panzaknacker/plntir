package idgen

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"io"
	"strings"
)

var encoding = base32.NewEncoding("0123456789abcdefghjkmnpqrstvwxyz").WithPadding(base32.NoPadding)

func New(prefix string) (string, error) {
	return NewFrom(prefix, rand.Reader)
}

func NewFrom(prefix string, source io.Reader) (string, error) {
	if prefix == "" || len(prefix) > 16 {
		return "", fmt.Errorf("invalid id prefix")
	}
	for _, r := range prefix {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') {
			return "", fmt.Errorf("invalid id prefix")
		}
	}
	random := make([]byte, 20)
	if _, err := io.ReadFull(source, random); err != nil {
		return "", fmt.Errorf("generate random id: %w", err)
	}
	return prefix + "_" + strings.ToLower(encoding.EncodeToString(random)), nil
}
