package archive

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestHTTPGrantAndObjectClientsKeepBearerURLBound(t *testing.T) {
	t.Parallel()
	body := []byte("encrypted-object-record")
	digest := sha256.Sum256(body)
	digestHex := hex.EncodeToString(digest[:])
	checksum := base64.StdEncoding.EncodeToString(digest[:])
	workID := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	objectID := "opaque-object"
	var server *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/grant", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.Header.Get("Idempotency-Key") != objectID {
			http.Error(writer, "bad request", http.StatusBadRequest)
			return
		}
		var grantRequest UploadGrantRequest
		decoder := json.NewDecoder(io.LimitReader(request.Body, 64<<10))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&grantRequest); err != nil || grantRequest.ObjectID != objectID || grantRequest.WorkID != workID || grantRequest.ContentSHA256 != digestHex {
			http.Error(writer, "bad payload", http.StatusBadRequest)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		json.NewEncoder(writer).Encode(UploadGrant{
			ObjectID:  objectID,
			Method:    http.MethodPut,
			URL:       server.URL + "/object",
			ExpiresAt: testNow.Add(4 * time.Minute),
			RequiredHeaders: map[string]string{
				"Content-Type":                "application/octet-stream",
				"Content-Length":              strconv.Itoa(len(body)),
				"x-amz-checksum-sha256":       checksum,
				"x-amz-meta-plntir-object-id": objectID,
				"x-amz-meta-plntir-work-id":   workID,
			},
		})
	})
	mux.HandleFunc("/object", func(writer http.ResponseWriter, request *http.Request) {
		received, _ := io.ReadAll(io.LimitReader(request.Body, 1024))
		if request.Method != http.MethodPut || string(received) != string(body) || request.Header.Get("x-amz-checksum-sha256") != checksum || request.Header.Get("x-amz-meta-plntir-object-id") != objectID || request.Header.Get("x-amz-meta-plntir-work-id") != workID {
			http.Error(writer, "binding mismatch", http.StatusBadRequest)
			return
		}
		writer.Header().Set("x-amz-checksum-sha256", checksum)
		writer.WriteHeader(http.StatusNoContent)
	})
	server = httptest.NewServer(mux)
	defer server.Close()
	request := UploadGrantRequest{DeviceID: "mac-1", ArchiveID: "archive-1", WorkID: workID, ObjectID: objectID, Method: http.MethodPut, ContentLength: int64(len(body)), ContentSHA256: digestHex, ChecksumSHA256: checksum}
	grantClient := HTTPGrantClient{Endpoint: server.URL + "/grant", Client: server.Client(), AllowLoopbackHTTPTest: true}
	grant, err := grantClient.Grant(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateGrant(grant, request, testNow, true); err != nil {
		t.Fatal(err)
	}
	objectClient := HTTPObjectUploader{Client: server.Client(), AllowLoopbackHTTPTest: true}
	if err := objectClient.Put(context.Background(), PutRequest{URL: grant.URL, Headers: grant.RequiredHeaders, Body: body, ContentSHA256: digestHex, ChecksumSHA256: checksum}); err != nil {
		t.Fatal(err)
	}
}

func TestGrantRejectsOverlongMissingAndDuplicateBindings(t *testing.T) {
	t.Parallel()
	request := UploadGrantRequest{WorkID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ObjectID: "object", Method: http.MethodPut, ContentLength: 42, ChecksumSHA256: "checksum"}
	base := UploadGrant{
		ObjectID:  request.ObjectID,
		Method:    http.MethodPut,
		URL:       "https://objects.example.invalid/object",
		ExpiresAt: testNow.Add(4 * time.Minute),
		RequiredHeaders: map[string]string{
			"content-type":                "application/octet-stream",
			"content-length":              "42",
			"x-amz-checksum-sha256":       request.ChecksumSHA256,
			"x-amz-meta-plntir-object-id": request.ObjectID,
			"x-amz-meta-plntir-work-id":   request.WorkID,
		},
	}
	if err := validateGrant(base, request, testNow, false); err != nil {
		t.Fatal(err)
	}
	overlong := base
	overlong.ExpiresAt = testNow.Add(5*time.Minute + time.Nanosecond)
	if err := validateGrant(overlong, request, testNow, false); err == nil {
		t.Fatal("grant longer than five minutes was accepted")
	}
	missing := base
	missing.RequiredHeaders = cloneHeaders(base.RequiredHeaders)
	delete(missing.RequiredHeaders, "x-amz-meta-plntir-work-id")
	if err := validateGrant(missing, request, testNow, false); err == nil {
		t.Fatal("grant missing work binding was accepted")
	}
	duplicate := base
	duplicate.RequiredHeaders = cloneHeaders(base.RequiredHeaders)
	duplicate.RequiredHeaders["Content-Type"] = "application/octet-stream"
	if err := validateGrant(duplicate, request, testNow, false); err == nil {
		t.Fatal("case-duplicate grant header was accepted")
	}
	if err := validateTransferURL("http://objects.example.invalid/object", true); err == nil {
		t.Fatal("test HTTP exception escaped loopback")
	}
}

func cloneHeaders(input map[string]string) map[string]string {
	output := make(map[string]string, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func TestHTTPClientsNeverFollowRedirects(t *testing.T) {
	t.Parallel()
	mux := http.NewServeMux()
	mux.HandleFunc("/redirect", func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, "/should-not-run", http.StatusTemporaryRedirect)
	})
	mux.HandleFunc("/should-not-run", func(writer http.ResponseWriter, request *http.Request) {
		t.Error("bearer request followed a redirect")
		writer.WriteHeader(http.StatusNoContent)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	body := []byte("ciphertext")
	digest := sha256.Sum256(body)
	client := HTTPObjectUploader{Client: server.Client(), AllowLoopbackHTTPTest: true}
	err := client.Put(context.Background(), PutRequest{URL: server.URL + "/redirect", Body: body, ContentSHA256: hex.EncodeToString(digest[:]), ChecksumSHA256: base64.StdEncoding.EncodeToString(digest[:])})
	if err == nil {
		t.Fatal("redirect response was accepted")
	}
}
