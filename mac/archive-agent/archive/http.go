package archive

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type HTTPGrantClient struct {
	Endpoint              string
	Client                *http.Client
	AllowLoopbackHTTPTest bool
}

func (client HTTPGrantClient) Grant(ctx context.Context, request UploadGrantRequest) (UploadGrant, error) {
	if err := validateTransferURL(client.Endpoint, client.AllowLoopbackHTTPTest); err != nil {
		return UploadGrant{}, fmt.Errorf("invalid archive grant endpoint: %w", err)
	}
	body, err := json.Marshal(request)
	if err != nil {
		return UploadGrant{}, err
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, client.Endpoint, bytes.NewReader(body))
	if err != nil {
		return UploadGrant{}, err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Accept", "application/json")
	httpRequest.Header.Set("Idempotency-Key", request.ObjectID)
	response, err := noRedirectClient(client.Client).Do(httpRequest)
	if err != nil {
		return UploadGrant{}, fmt.Errorf("request archive upload grant: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return UploadGrant{}, fmt.Errorf("archive upload grant returned status %d", response.StatusCode)
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
	if err != nil {
		return UploadGrant{}, err
	}
	if len(content) > 64<<10 {
		return UploadGrant{}, errors.New("archive upload grant response is oversized")
	}
	var grant UploadGrant
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&grant); err != nil {
		return UploadGrant{}, fmt.Errorf("decode archive upload grant: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return UploadGrant{}, err
	}
	return grant, nil
}

type HTTPObjectUploader struct {
	Client                *http.Client
	AllowLoopbackHTTPTest bool
}

func (uploader HTTPObjectUploader) Put(ctx context.Context, request PutRequest) error {
	if err := validateTransferURL(request.URL, uploader.AllowLoopbackHTTPTest); err != nil {
		return fmt.Errorf("invalid archive upload URL: %w", err)
	}
	if int64(len(request.Body)) <= 0 || !validHexDigest(request.ContentSHA256) || request.ChecksumSHA256 == "" {
		return errors.New("archive PUT metadata is invalid")
	}
	digest := sha256.Sum256(request.Body)
	if hex.EncodeToString(digest[:]) != request.ContentSHA256 || base64.StdEncoding.EncodeToString(digest[:]) != request.ChecksumSHA256 {
		return errors.New("archive PUT body does not match its declared checksums")
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPut, request.URL, bytes.NewReader(request.Body))
	if err != nil {
		return err
	}
	httpRequest.ContentLength = int64(len(request.Body))
	for name, value := range request.Headers {
		lower := strings.ToLower(name)
		if lower == "authorization" || lower == "cookie" || lower == "host" || strings.ContainsAny(name, "\r\n") || strings.ContainsAny(value, "\r\n") {
			return errors.New("archive grant contains a forbidden upload header")
		}
		httpRequest.Header.Set(name, value)
	}
	response, err := noRedirectClient(uploader.Client).Do(httpRequest)
	if err != nil {
		return fmt.Errorf("upload encrypted archive object: %w", err)
	}
	defer response.Body.Close()
	io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusCreated && response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("encrypted archive PUT returned status %d", response.StatusCode)
	}
	if returned := response.Header.Get("x-amz-checksum-sha256"); returned != "" && returned != request.ChecksumSHA256 {
		return errors.New("encrypted archive PUT returned a different checksum")
	}
	return nil
}

func validateGrant(grant UploadGrant, request UploadGrantRequest, now time.Time, allowLoopbackHTTP bool) error {
	if grant.ObjectID != request.ObjectID || grant.Method != http.MethodPut {
		return errors.New("archive grant is not bound to the requested method and object")
	}
	if grant.ExpiresAt.IsZero() || !grant.ExpiresAt.After(now) || grant.ExpiresAt.Sub(now) > 5*time.Minute {
		return errors.New("archive grant lifetime is invalid")
	}
	if err := validateTransferURL(grant.URL, allowLoopbackHTTP); err != nil {
		return err
	}
	headers := make(map[string]string, len(grant.RequiredHeaders))
	for name, value := range grant.RequiredHeaders {
		lower := strings.ToLower(name)
		if _, duplicate := headers[lower]; duplicate {
			return errors.New("archive grant contains duplicate header names")
		}
		headers[lower] = value
	}
	if headers["x-amz-checksum-sha256"] != request.ChecksumSHA256 || headers["content-type"] != "application/octet-stream" {
		return errors.New("archive grant is not checksum- and content-type-bound")
	}
	if headers["content-length"] != strconv.FormatInt(request.ContentLength, 10) {
		return errors.New("archive grant content length does not match")
	}
	if headers["x-amz-meta-plntir-object-id"] != request.ObjectID || headers["x-amz-meta-plntir-work-id"] != request.WorkID {
		return errors.New("archive grant is not bound to its opaque object and work IDs")
	}
	return nil
}

func validateTransferURL(raw string, allowLoopbackHTTP bool) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return errors.New("transfer URL is malformed")
	}
	if parsed.Scheme == "https" {
		return nil
	}
	if parsed.Scheme == "http" && allowLoopbackHTTP {
		host := parsed.Hostname()
		if host == "127.0.0.1" || host == "::1" || host == "localhost" {
			return nil
		}
	}
	return errors.New("transfer URL must use HTTPS")
}

func noRedirectClient(input *http.Client) *http.Client {
	if input == nil {
		input = &http.Client{Timeout: 30 * time.Second}
	}
	clone := *input
	clone.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &clone
}
