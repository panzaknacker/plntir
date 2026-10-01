package wazuhintegrity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadsOnlyPrivateStrictMTLSFiles(t *testing.T) {
	now := time.Now().UTC()
	certificatePEM, privateKeyPEM, rootPEM := testPEMMaterials(t, now)
	directory := t.TempDir()
	certificatePath := privateTestFile(t, directory, "client.pem", certificatePEM)
	privateKeyPath := privateTestFile(t, directory, "client-key.pem", privateKeyPEM)
	rootPath := privateTestFile(t, directory, "root.pem", rootPEM)
	certificate, roots, err := LoadMTLSFiles(MTLSFileOptions{
		CertificatePath: certificatePath, PrivateKeyPath: privateKeyPath, RootCAPath: rootPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(certificate.Certificate) == 0 || certificate.PrivateKey == nil || len(roots.Subjects()) != 1 {
		t.Fatal("loaded mTLS material is incomplete")
	}

	if err := os.Chmod(privateKeyPath, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadMTLSFiles(MTLSFileOptions{
		CertificatePath: certificatePath, PrivateKeyPath: privateKeyPath, RootCAPath: rootPath,
	}); err == nil {
		t.Fatal("group-readable private key was accepted")
	}
	if err := os.Chmod(privateKeyPath, 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(directory, "linked-key.pem")
	if err := os.Symlink(privateKeyPath, symlink); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadMTLSFiles(MTLSFileOptions{
		CertificatePath: certificatePath, PrivateKeyPath: symlink, RootCAPath: rootPath,
	}); err == nil {
		t.Fatal("symlinked private key was accepted")
	}
}

func TestLoadsOnlyEd25519PKCS8SigningKey(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	encoded, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	path := privateTestFile(t, directory, "signing.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}))
	loaded, err := LoadEd25519PrivateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !privateKey.Equal(loaded) {
		t.Fatal("loaded signing key differs")
	}
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaDER, _ := x509.MarshalPKCS8PrivateKey(rsaKey)
	rsaPath := privateTestFile(t, directory, "rsa.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rsaDER}))
	if _, err := LoadEd25519PrivateKey(rsaPath); err == nil {
		t.Fatal("RSA key was accepted as Ed25519 signing key")
	}
}

func TestRootBundleRejectsPrivateKeyAndNonCA(t *testing.T) {
	now := time.Now().UTC()
	certificatePEM, privateKeyPEM, _ := testPEMMaterials(t, now)
	if _, err := strictCertPool(append(certificatePEM, privateKeyPEM...)); err == nil {
		t.Fatal("root bundle containing a private key was accepted")
	}
	if _, err := strictCertPool(certificatePEM); err == nil {
		t.Fatal("leaf certificate was accepted as a trust root")
	}
}

func privateTestFile(t *testing.T, directory, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func testPEMMaterials(t *testing.T, now time.Time) ([]byte, []byte, []byte) {
	t.Helper()
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(11), Subject: pkix.Name{CommonName: "Plntir root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCertificate, _ := x509.ParseCertificate(caDER)
	clientKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(12), Subject: pkix.Name{CommonName: "plntir-siem-01"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCertificate, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, _ := x509.MarshalPKCS8PrivateKey(clientKey)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
}
