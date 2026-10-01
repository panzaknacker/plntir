package scanresultbroker

import (
	"bytes"
	"context"
	"crypto/ed25519"
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
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"plntir/core/internal/envelope"
	"plntir/core/internal/scanresult"
)

const maximumRequestBytes = 32 << 10

var (
	hexSHA256    = regexp.MustCompile(`^[a-f0-9]{64}$`)
	apiIDPattern = regexp.MustCompile(`^[a-z0-9]{10}$`)
	accountID    = regexp.MustCompile(`^[0-9]{12}$`)
)

type QueueAPI interface {
	SendMessage(context.Context, *sqs.SendMessageInput, ...func(*sqs.Options)) (*sqs.SendMessageOutput, error)
}

type Configuration struct {
	ScannerVerifyKey      ed25519.PublicKey
	ClientCertFingerprint string
	ExpectedAPIID         string
	ExpectedDomainName    string
	AWSAccountID          string
	QueueURL              string
}

type Handler struct {
	queue  QueueAPI
	config Configuration
	now    func() time.Time
	logger *slog.Logger
}

func ConfigurationFromEnvironment() (Configuration, error) {
	encoded := os.Getenv("PLNTIR_SCANNER_RESULT_VERIFY_KEY")
	key, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(key) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(key) != encoded {
		return Configuration{}, errors.New("scanner result verification key is invalid")
	}
	configuration := Configuration{
		ScannerVerifyKey:      ed25519.PublicKey(key),
		ClientCertFingerprint: strings.ToLower(os.Getenv("PLNTIR_SCANNER_CLIENT_CERT_SHA256")),
		ExpectedAPIID:         os.Getenv("PLNTIR_API_GATEWAY_ID"),
		ExpectedDomainName:    strings.ToLower(os.Getenv("PLNTIR_API_DOMAIN")),
		AWSAccountID:          os.Getenv("PLNTIR_AWS_ACCOUNT_ID"),
		QueueURL:              os.Getenv("PLNTIR_SCAN_RESULT_QUEUE_URL"),
	}
	if os.Getenv("AWS_REGION") != "eu-central-1" {
		return Configuration{}, errors.New("scan result broker is restricted to eu-central-1")
	}
	if err := configuration.Validate(); err != nil {
		return Configuration{}, err
	}
	return configuration, nil
}

func (configuration Configuration) Validate() error {
	if len(configuration.ScannerVerifyKey) != ed25519.PublicKeySize {
		return errors.New("scanner result verification key is invalid")
	}
	if !hexSHA256.MatchString(configuration.ClientCertFingerprint) {
		return errors.New("scanner client certificate fingerprint is invalid")
	}
	if !apiIDPattern.MatchString(configuration.ExpectedAPIID) || !accountID.MatchString(configuration.AWSAccountID) {
		return errors.New("API or AWS account binding is invalid")
	}
	if configuration.ExpectedDomainName == "" || len(configuration.ExpectedDomainName) > 253 || configuration.ExpectedDomainName == "plntir.example" ||
		strings.HasSuffix(configuration.ExpectedDomainName, ".plntir.example") {
		return errors.New("mTLS broker domain must be an unproxied non-plntir.example name")
	}
	queueURL, err := url.Parse(configuration.QueueURL)
	wantedPath := "/" + configuration.AWSAccountID + "/plntir-scan-results.fifo"
	if err != nil || queueURL.Scheme != "https" || queueURL.Host != "sqs.eu-central-1.amazonaws.com" ||
		queueURL.Path != wantedPath || queueURL.RawQuery != "" || queueURL.Fragment != "" || queueURL.User != nil {
		return errors.New("scan result queue URL is not the bound eu-central-1 FIFO queue")
	}
	return nil
}

func New(queue QueueAPI, configuration Configuration, logger *slog.Logger) (*Handler, error) {
	if queue == nil {
		return nil, errors.New("SQS client is required")
	}
	if err := configuration.Validate(); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	return &Handler{queue: queue, config: configuration, now: time.Now, logger: logger}, nil
}

func (handler *Handler) Handle(ctx context.Context, request events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	if request.RequestContext.APIID != handler.config.ExpectedAPIID ||
		!strings.EqualFold(request.RequestContext.DomainName, handler.config.ExpectedDomainName) {
		return problem(http.StatusForbidden, "invalid_gateway"), nil
	}
	if request.RawQueryString != "" || request.RawPath != "/v1/results" {
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
	var value envelope.Envelope
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return problem(http.StatusBadRequest, "invalid_request"), nil
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return problem(http.StatusBadRequest, "invalid_request"), nil
	}
	if header(request.Headers, "idempotency-key") != value.DeduplicationID {
		return problem(http.StatusBadRequest, "invalid_idempotency_key"), nil
	}
	if _, err := scanresult.Verify(value, handler.config.ScannerVerifyKey, handler.now()); err != nil {
		return problem(http.StatusBadRequest, "invalid_scan_result"), nil
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return events.APIGatewayV2HTTPResponse{}, err
	}
	output, err := handler.queue.SendMessage(ctx, &sqs.SendMessageInput{
		QueueUrl:               aws.String(handler.config.QueueURL),
		MessageBody:            aws.String(string(canonical)),
		MessageDeduplicationId: aws.String(value.DeduplicationID),
		MessageGroupId:         aws.String("scan-results"),
	})
	if err != nil || output == nil || output.MessageId == nil || *output.MessageId == "" {
		handler.logger.Error("scan result queue unavailable", "job_id", value.DeduplicationID,
			"request_id", request.RequestContext.RequestID)
		return problem(http.StatusServiceUnavailable, "result_queue_unavailable"), nil
	}
	responseBody, _ := json.Marshal(map[string]string{"state": "accepted", "deduplication_id": value.DeduplicationID})
	return events.APIGatewayV2HTTPResponse{
		StatusCode: http.StatusAccepted,
		Headers:    responseHeaders("application/json; charset=utf-8"),
		Body:       string(responseBody),
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
	return events.APIGatewayV2HTTPResponse{StatusCode: status, Headers: responseHeaders("application/problem+json; charset=utf-8"), Body: string(body)}
}

func responseHeaders(contentType string) map[string]string {
	return map[string]string{
		"Cache-Control": "no-store", "Content-Type": contentType,
		"Content-Security-Policy": "default-src 'none'", "X-Content-Type-Options": "nosniff",
	}
}

func (configuration Configuration) String() string {
	return fmt.Sprintf("scan-result-broker[%s]", configuration.ExpectedAPIID)
}
