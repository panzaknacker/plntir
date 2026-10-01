package webconsole

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
)

const (
	passwordScheme     = "pbkdf2-sha256"
	defaultIterations  = 600000
	minimumIterations  = 310000
	maximumIterations  = 2000000
	passwordDerivedLen = 32
)

var authUsernamePattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

type AuthFile struct {
	SchemaVersion int    `json:"schema_version"`
	Username      string `json:"username"`
	PasswordHash  string `json:"password_hash"`
}

type PasswordVerifier struct {
	username   string
	iterations int
	salt       []byte
	expected   []byte
}

func HashPassword(password []byte, iterations int) (string, error) {
	if len(password) < 16 || len(password) > 1024 {
		return "", errors.New("dashboard password must be between 16 and 1024 bytes")
	}
	if iterations == 0 {
		iterations = defaultIterations
	}
	if iterations < minimumIterations || iterations > maximumIterations {
		return "", fmt.Errorf("iterations must be between %d and %d", minimumIterations, maximumIterations)
	}
	salt := make([]byte, 24)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	derived := pbkdf2SHA256(password, salt, iterations, passwordDerivedLen)
	defer clearBytes(derived)
	return strings.Join([]string{
		passwordScheme,
		strconv.Itoa(iterations),
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(derived),
	}, "$"), nil
}

func LoadPasswordVerifier(path string) (*PasswordVerifier, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o137 != 0 {
		return nil, errors.New("auth file must be regular with no execute, group-write, or world permissions")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var auth AuthFile
	if err := decoder.Decode(&auth); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("auth file contains trailing JSON data")
	}
	if auth.SchemaVersion != 1 || !authUsernamePattern.MatchString(auth.Username) {
		return nil, errors.New("invalid dashboard auth file")
	}
	parts := strings.Split(auth.PasswordHash, "$")
	if len(parts) != 4 || parts[0] != passwordScheme {
		return nil, errors.New("unsupported dashboard password hash")
	}
	iterations, err := strconv.Atoi(parts[1])
	if err != nil || iterations < minimumIterations || iterations > maximumIterations {
		return nil, errors.New("invalid dashboard password iterations")
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil || len(salt) < 16 || len(salt) > 64 {
		return nil, errors.New("invalid dashboard password salt")
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil || len(expected) != passwordDerivedLen {
		return nil, errors.New("invalid dashboard password digest")
	}
	return &PasswordVerifier{
		username:   auth.Username,
		iterations: iterations,
		salt:       salt,
		expected:   expected,
	}, nil
}

func (v *PasswordVerifier) Username() string {
	return v.username
}

func (v *PasswordVerifier) Verify(username string, password []byte) bool {
	usernameOK := subtle.ConstantTimeCompare([]byte(username), []byte(v.username))
	actual := pbkdf2SHA256(password, v.salt, v.iterations, len(v.expected))
	passwordOK := subtle.ConstantTimeCompare(actual, v.expected)
	clearBytes(actual)
	return usernameOK&passwordOK == 1
}

func pbkdf2SHA256(password, salt []byte, iterations, length int) []byte {
	result := make([]byte, 0, length)
	var blockIndex uint32 = 1
	for len(result) < length {
		mac := hmac.New(sha256.New, password)
		_, _ = mac.Write(salt)
		var counter [4]byte
		binary.BigEndian.PutUint32(counter[:], blockIndex)
		_, _ = mac.Write(counter[:])
		u := mac.Sum(nil)
		t := append([]byte(nil), u...)
		for iteration := 1; iteration < iterations; iteration++ {
			mac = hmac.New(sha256.New, password)
			_, _ = mac.Write(u)
			clearBytes(u)
			u = mac.Sum(nil)
			for index := range t {
				t[index] ^= u[index]
			}
		}
		clearBytes(u)
		result = append(result, t...)
		clearBytes(t)
		blockIndex++
	}
	return result[:length]
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

// ClearPassword lets the command entrypoint wipe its temporary stdin buffer.
// callers should still avoid placing passwords in command-line arguments.
func ClearPassword(value []byte) {
	clearBytes(value)
}
