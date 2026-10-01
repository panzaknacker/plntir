package kmsbroker

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"plntir/core/internal/scanmeta"
)

const (
	maximumRequestBytes = 32 << 10
	maximumJobAge       = 8 * 24 * time.Hour
	maximumClockSkew    = 5 * time.Minute
)

var (
	hexSHA256    = regexp.MustCompile(`^[a-f0-9]{64}$`)
	safeID       = regexp.MustCompile(`^[a-z][a-z0-9]{0,15}_[0-9a-hjkmnp-tv-z]{32}$`)
	kmsKeyARN    = regexp.MustCompile(`^arn:aws:kms:eu-central-1:[0-9]{12}:key/[0-9a-f-]{36}$`)
	apiIDPattern = regexp.MustCompile(`^[a-z0-9]{10}$`)
)

type KMSAPI interface {
	Decrypt(context.Context, *kms.DecryptInput, ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

type Configuration struct {
	KMSKeyARN             string
	CoreVerifyKey         ed25519.PublicKey
	ClientCertFingerprint string
	ExpectedAccountID     string
	ExpectedBucket        string
	ExpectedAPIID         string
	ExpectedDomainName    string
}

type Handler struct {
	kms    KMSAPI
	config Configuration
	now    func() time.Time
	random io.Reader
	logger *slog.Logger
}

type rewrapRequest struct {
	EnvelopeVersion    int     `json:"envelope_version"`
	Job                scanJob `json:"job"`
	ScanSessionID      string  `json:"scan_session_id"`
	ContainerPublicKey string  `json:"container_public_key"`
}

type scanJob struct {
	Account             string `json:"account"`
	Action              string `json:"action"`
	Bucket              string `json:"bucket"`
	ObjectKey           string `json:"objectKey"`
	CiphertextSize      int64  `json:"ciphertextSize"`
	ETag                string `json:"eTag"`
	EventTime           string `json:"eventTime"`
	JobID               string `json:"jobID"`
	FileVersionID       string `json:"fileVersionID"`
	MediaKind           string `json:"mediaKind"`
	ManifestSHA256      string `json:"manifestSHA256"`
	KMSCiphertext       string `json:"kmsCiphertext"`
	KMSCiphertextSHA256 string `json:"kmsCiphertextSHA256"`
	PlaintextSize       int64  `json:"plaintextSize"`
	ChunkSize           int64  `json:"chunkSize"`
	NoncePrefix         string `json:"noncePrefix"`
	SignedAt            string `json:"signedAt"`
	Signature           string `json:"signature"`
}

type rewrapResponse struct {
	EnvelopeVersion int    `json:"envelope_version"`
	JobID           string `json:"job_id"`
	ScanSessionID   string `json:"scan_session_id"`
	BrokerPublicKey string `json:"broker_public_key"`
	WrapNonce       string `json:"wrap_nonce"`
	WrappedDEK      string `json:"wrapped_dek"`
}

func ConfigurationFromEnvironment() (Configuration, error) {
	decodePublicKey := func(name string) (ed25519.PublicKey, error) {
		encoded := os.Getenv(name)
		decoded, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
		if err != nil || len(decoded) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(decoded) != encoded {
			return nil, fmt.Errorf("%s is not a canonical Ed25519 public key", name)
		}
		return ed25519.PublicKey(decoded), nil
	}
	verifyKey, err := decodePublicKey("PLNTIR_CORE_SCAN_VERIFY_KEY")
	if err != nil {
		return Configuration{}, err
	}
	configuration := Configuration{
		KMSKeyARN:             os.Getenv("PLNTIR_KMS_KEY_ARN"),
		CoreVerifyKey:         verifyKey,
		ClientCertFingerprint: strings.ToLower(os.Getenv("PLNTIR_SCANNER_CLIENT_CERT_SHA256")),
		ExpectedAccountID:     os.Getenv("PLNTIR_CLOUDFLARE_ACCOUNT_ID"),
		ExpectedBucket:        os.Getenv("PLNTIR_R2_BUCKET"),
		ExpectedAPIID:         os.Getenv("PLNTIR_API_GATEWAY_ID"),
		ExpectedDomainName:    strings.ToLower(os.Getenv("PLNTIR_API_DOMAIN")),
	}
	if os.Getenv("AWS_REGION") != "eu-central-1" {
		return Configuration{}, errors.New("KMS broker is restricted to eu-central-1")
	}
	if err := configuration.Validate(); err != nil {
		return Configuration{}, err
	}
	return configuration, nil
}

func (configuration Configuration) Validate() error {
	if !kmsKeyARN.MatchString(configuration.KMSKeyARN) {
		return errors.New("KMS key must be an eu-central-1 key ARN")
	}
	if len(configuration.CoreVerifyKey) != ed25519.PublicKeySize {
		return errors.New("Core scan verification key is invalid")
	}
	if !hexSHA256.MatchString(configuration.ClientCertFingerprint) {
		return errors.New("scanner client certificate fingerprint is invalid")
	}
	if !regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(configuration.ExpectedAccountID) {
		return errors.New("Cloudflare account id is invalid")
	}
	if !regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`).MatchString(configuration.ExpectedBucket) {
		return errors.New("R2 bucket is invalid")
	}
	if !apiIDPattern.MatchString(configuration.ExpectedAPIID) {
		return errors.New("API Gateway id is invalid")
	}
	if configuration.ExpectedDomainName == "" || len(configuration.ExpectedDomainName) > 253 ||
		configuration.ExpectedDomainName == "plntir.example" || strings.HasSuffix(configuration.ExpectedDomainName, ".plntir.example") {
		return errors.New("mTLS broker domain must be a configured unproxied non-plntir.example name")
	}
	return nil
}

func New(client KMSAPI, configuration Configuration, logger *slog.Logger) (*Handler, error) {
	if client == nil {
		return nil, errors.New("KMS client is required")
	}
	if err := configuration.Validate(); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	return &Handler{kms: client, config: configuration, now: time.Now, random: rand.Reader, logger: logger}, nil
}

func (handler *Handler) Handle(ctx context.Context, request events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	if request.RequestContext.APIID != handler.config.ExpectedAPIID || !strings.EqualFold(request.RequestContext.DomainName, handler.config.ExpectedDomainName) {
		return problem(http.StatusForbidden, "invalid_gateway"), nil
	}
	if request.RawQueryString != "" || request.RawPath != "/v1/rewrap" {
		return problem(http.StatusNotFound, "not_found"), nil
	}
	if request.RequestContext.HTTP.Method != http.MethodPost {
		return problem(http.StatusMethodNotAllowed, "method_not_allowed"), nil
	}
	if !handler.validClientCertificate(request.RequestContext.Authentication.ClientCert.ClientCertPem) {
		return problem(http.StatusForbidden, "client_certificate_rejected"), nil
	}
	mediaType, parameters, err := mime.ParseMediaType(header(request.Headers, "content-type"))
	if err != nil || mediaType != "application/json" || (parameters["charset"] != "" && !strings.EqualFold(parameters["charset"], "utf-8")) {
		return problem(http.StatusUnsupportedMediaType, "content_type_rejected"), nil
	}
	body, err := requestBody(request)
	if err != nil {
		return problem(http.StatusBadRequest, "invalid_request"), nil
	}
	var input rewrapRequest
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return problem(http.StatusBadRequest, "invalid_request"), nil
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return problem(http.StatusBadRequest, "invalid_request"), nil
	}
	if header(request.Headers, "idempotency-key") != input.Job.JobID {
		return problem(http.StatusBadRequest, "invalid_idempotency_key"), nil
	}
	containerPublicKey, kmsCiphertext, err := handler.validateRequest(input)
	if err != nil {
		return problem(http.StatusBadRequest, "invalid_scan_job"), nil
	}
	plaintext, err := handler.decrypt(ctx, input.Job, kmsCiphertext)
	if err != nil {
		handler.logger.Error("KMS decrypt failed", "job_id", input.Job.JobID, "request_id", request.RequestContext.RequestID)
		return problem(http.StatusServiceUnavailable, "key_service_unavailable"), nil
	}
	defer clear(plaintext)
	result, err := handler.wrap(input, containerPublicKey, plaintext)
	if err != nil {
		handler.logger.Error("ephemeral key wrap failed", "job_id", input.Job.JobID, "request_id", request.RequestContext.RequestID)
		return problem(http.StatusServiceUnavailable, "key_wrap_unavailable"), nil
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return events.APIGatewayV2HTTPResponse{}, err
	}
	return events.APIGatewayV2HTTPResponse{
		StatusCode: http.StatusOK,
		Headers:    responseHeaders("application/json; charset=utf-8"),
		Body:       string(encoded),
	}, nil
}

func (handler *Handler) validClientCertificate(encoded string) bool {
	block, rest := pem.Decode([]byte(encoded))
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return false
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil || handler.now().Before(certificate.NotBefore) || !handler.now().Before(certificate.NotAfter) || certificate.IsCA {
		return false
	}
	clientUsage := false
	for _, usage := range certificate.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth || usage == x509.ExtKeyUsageAny {
			clientUsage = true
		}
	}
	if !clientUsage {
		return false
	}
	fingerprint := sha256.Sum256(certificate.Raw)
	expected, err := hex.DecodeString(handler.config.ClientCertFingerprint)
	return err == nil && subtle.ConstantTimeCompare(fingerprint[:], expected) == 1
}

func (handler *Handler) validateRequest(input rewrapRequest) (*ecdh.PublicKey, []byte, error) {
	if input.EnvelopeVersion != 1 || !safeID.MatchString(input.ScanSessionID) || !strings.HasPrefix(input.ScanSessionID, "scan_") {
		return nil, nil, errors.New("unsupported envelope or invalid scan session")
	}
	if input.Job.Account != handler.config.ExpectedAccountID || input.Job.Bucket != handler.config.ExpectedBucket {
		return nil, nil, errors.New("job binding does not match broker")
	}
	if input.Job.Action != "PutObject" && input.Job.Action != "CompleteMultipartUpload" {
		return nil, nil, errors.New("job action is invalid")
	}
	metadata := scanmeta.Metadata{
		JobID: input.Job.JobID, FileVersionID: input.Job.FileVersionID, MediaKind: input.Job.MediaKind,
		ManifestSHA256: input.Job.ManifestSHA256, KMSCiphertext: input.Job.KMSCiphertext,
		KMSCiphertextSHA256: input.Job.KMSCiphertextSHA256, PlaintextSize: input.Job.PlaintextSize,
		ChunkSize: input.Job.ChunkSize, NoncePrefix: input.Job.NoncePrefix,
		SignedAt: input.Job.SignedAt, Signature: input.Job.Signature,
	}
	if err := scanmeta.Verify(input.Job.Account, input.Job.Bucket, input.Job.ObjectKey, input.Job.CiphertextSize, metadata, handler.config.CoreVerifyKey); err != nil {
		return nil, nil, err
	}
	signedAt, err := time.Parse(time.RFC3339, input.Job.SignedAt)
	if err != nil || signedAt.After(handler.now().Add(maximumClockSkew)) || handler.now().Sub(signedAt) > maximumJobAge {
		return nil, nil, errors.New("scan job is outside the rewrap window")
	}
	eventTime, err := time.Parse(time.RFC3339Nano, input.Job.EventTime)
	if err != nil || eventTime.Sub(signedAt) < -maximumClockSkew || eventTime.Sub(signedAt) > 48*time.Hour {
		return nil, nil, errors.New("scan event is outside the upload window")
	}
	containerBytes, err := decodeCanonicalBase64URL(input.ContainerPublicKey, 32)
	if err != nil {
		return nil, nil, err
	}
	containerPublicKey, err := ecdh.X25519().NewPublicKey(containerBytes)
	if err != nil {
		return nil, nil, errors.New("container public key is invalid")
	}
	kmsCiphertext, err := decodeCanonicalBase64URL(input.Job.KMSCiphertext, -1)
	if err != nil || len(kmsCiphertext) < 1 || len(kmsCiphertext) > 6144 {
		return nil, nil, errors.New("KMS ciphertext is invalid")
	}
	return containerPublicKey, kmsCiphertext, nil
}

func (handler *Handler) decrypt(ctx context.Context, job scanJob, ciphertext []byte) ([]byte, error) {
	output, err := handler.kms.Decrypt(ctx, &kms.DecryptInput{
		CiphertextBlob:      ciphertext,
		EncryptionAlgorithm: kmstypes.EncryptionAlgorithmSpecSymmetricDefault,
		EncryptionContext:   EncryptionContext(job.FileVersionID, job.ObjectKey),
		KeyId:               aws.String(handler.config.KMSKeyARN),
	})
	if err != nil || output == nil || len(output.Plaintext) != 32 || output.KeyId == nil || *output.KeyId != handler.config.KMSKeyARN {
		if output != nil {
			clear(output.Plaintext)
		}
		return nil, errors.New("KMS did not return the expected AES-256 key")
	}
	return output.Plaintext, nil
}

func EncryptionContext(fileVersionID, objectKey string) map[string]string {
	return map[string]string{
		"plntir-purpose":         "file-dek",
		"plntir-file-version-id": fileVersionID,
		"plntir-object-key":      objectKey,
	}
}

func (handler *Handler) wrap(input rewrapRequest, containerPublicKey *ecdh.PublicKey, plaintext []byte) (rewrapResponse, error) {
	brokerPrivateKey, err := ecdh.X25519().GenerateKey(handler.random)
	if err != nil {
		return rewrapResponse{}, err
	}
	sharedSecret, err := brokerPrivateKey.ECDH(containerPublicKey)
	if err != nil {
		return rewrapResponse{}, err
	}
	defer clear(sharedSecret)
	containerEncoded := base64.RawURLEncoding.EncodeToString(containerPublicKey.Bytes())
	brokerEncoded := base64.RawURLEncoding.EncodeToString(brokerPrivateKey.PublicKey().Bytes())
	salt := wrapSalt(input.Job.JobID, input.Job.FileVersionID, input.Job.ObjectKey, input.ScanSessionID)
	wrappingKey, err := hkdf.Key(sha256.New, sharedSecret, salt[:], "plntir-scan-dek-wrap-v1", 32)
	if err != nil {
		return rewrapResponse{}, err
	}
	defer clear(wrappingKey)
	block, err := aes.NewCipher(wrappingKey)
	if err != nil {
		return rewrapResponse{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return rewrapResponse{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(handler.random, nonce); err != nil {
		return rewrapResponse{}, err
	}
	aad := wrapAAD(input.Job.JobID, input.Job.FileVersionID, input.Job.ObjectKey, input.ScanSessionID, containerEncoded, brokerEncoded)
	wrapped := gcm.Seal(nil, nonce, plaintext, aad)
	return rewrapResponse{
		EnvelopeVersion: 1,
		JobID:           input.Job.JobID,
		ScanSessionID:   input.ScanSessionID,
		BrokerPublicKey: brokerEncoded,
		WrapNonce:       base64.RawURLEncoding.EncodeToString(nonce),
		WrappedDEK:      base64.RawURLEncoding.EncodeToString(wrapped),
	}, nil
}

func wrapSalt(jobID, fileVersionID, objectKey, sessionID string) [32]byte {
	return sha256.Sum256([]byte(strings.Join([]string{
		"plntir-scan-dek-wrap-salt-v1", jobID, fileVersionID, objectKey, sessionID, "",
	}, "\n")))
}

func wrapAAD(jobID, fileVersionID, objectKey, sessionID, containerPublicKey, brokerPublicKey string) []byte {
	return []byte(strings.Join([]string{
		"plntir-scan-dek-wrap-aad-v1", jobID, fileVersionID, objectKey, sessionID,
		containerPublicKey, brokerPublicKey, "",
	}, "\n"))
}

func requestBody(request events.APIGatewayV2HTTPRequest) ([]byte, error) {
	if len(request.Body) > maximumRequestBytes*2 {
		return nil, errors.New("request body is too large")
	}
	var body []byte
	var err error
	if request.IsBase64Encoded {
		body, err = base64.StdEncoding.Strict().DecodeString(request.Body)
	} else {
		body = []byte(request.Body)
	}
	if err != nil || len(body) == 0 || len(body) > maximumRequestBytes {
		return nil, errors.New("request body is invalid")
	}
	return body, nil
}

func decodeCanonicalBase64URL(value string, expectedLength int) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value || (expectedLength >= 0 && len(decoded) != expectedLength) {
		return nil, errors.New("value is not canonical base64url")
	}
	return decoded, nil
}

func header(headers map[string]string, wanted string) string {
	for key, value := range headers {
		if strings.EqualFold(key, wanted) {
			return value
		}
	}
	return ""
}

func problem(status int, code string) events.APIGatewayV2HTTPResponse {
	body, _ := json.Marshal(map[string]string{"type": "about:blank", "title": http.StatusText(status), "code": code})
	return events.APIGatewayV2HTTPResponse{
		StatusCode: status,
		Headers:    responseHeaders("application/problem+json; charset=utf-8"),
		Body:       string(body),
	}
}

func responseHeaders(contentType string) map[string]string {
	return map[string]string{
		"Cache-Control":           "no-store",
		"Content-Type":            contentType,
		"Content-Security-Policy": "default-src 'none'",
		"X-Content-Type-Options":  "nosniff",
	}
}
