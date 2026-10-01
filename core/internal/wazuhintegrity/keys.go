package wazuhintegrity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

const maximumKeyMaterialBytes = 64 << 10

type MTLSFileOptions struct {
	CertificatePath string
	PrivateKeyPath  string
	RootCAPath      string
}

func LoadMTLSFiles(options MTLSFileOptions) (tls.Certificate, *x509.CertPool, error) {
	certificatePEM, err := readPrivateFile(options.CertificatePath, maximumKeyMaterialBytes)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("load mTLS certificate: %w", err)
	}
	privateKeyPEM, err := readPrivateFile(options.PrivateKeyPath, maximumKeyMaterialBytes)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("load mTLS private key: %w", err)
	}
	rootPEM, err := readPrivateFile(options.RootCAPath, maximumKeyMaterialBytes)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("load mTLS root CA: %w", err)
	}
	certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		return tls.Certificate{}, nil, errors.New("mTLS certificate and private key do not form a valid pair")
	}
	roots, err := strictCertPool(rootPEM)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	return certificate, roots, nil
}

func LoadEd25519PrivateKey(path string) (ed25519.PrivateKey, error) {
	encoded, err := readPrivateFile(path, maximumKeyMaterialBytes)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(encoded)
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("signing key must be one unencrypted PKCS#8 PRIVATE KEY PEM block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("decode Ed25519 PKCS#8 signing key")
	}
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("signing key is not Ed25519")
	}
	return append(ed25519.PrivateKey(nil), privateKey...), nil
}

func strictCertPool(encoded []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	rest := encoded
	count := 0
	for len(bytes.TrimSpace(rest)) != 0 {
		block, remaining := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errors.New("mTLS root file must contain only CERTIFICATE PEM blocks")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !certificate.IsCA || certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, errors.New("mTLS root file contains an invalid non-CA certificate")
		}
		pool.AddCert(certificate)
		count++
		rest = remaining
	}
	if count == 0 {
		return nil, errors.New("mTLS root file contains no CA certificate")
	}
	return pool, nil
}

func readPrivateFile(path string, maximum int64) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || maximum < 1 {
		return nil, errors.New("private file path must be clean and absolute")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !privateRegularFile(info) {
		return nil, errors.New("private file must be an owned 0600 regular file")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !privateRegularFile(openedInfo) || !os.SameFile(info, openedInfo) {
		return nil, errors.New("private file identity changed while opening")
	}
	content, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(content) == 0 || int64(len(content)) > maximum {
		return nil, errors.New("private file is empty, oversized, or unreadable")
	}
	return content, nil
}
