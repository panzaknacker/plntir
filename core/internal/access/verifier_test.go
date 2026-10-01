package access

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"
)

type fakeVerifier struct {
	principal Principal
	err       error
	token     string
}

func (f *fakeVerifier) Verify(_ context.Context, token string) (Principal, error) {
	f.token = token
	return f.principal, f.err
}

func TestFromRequestUsesOriginAssertionHeader(t *testing.T) {
	request := httptest.NewRequest("GET", "https://admin.plntir.example/api/v1/admin/health", nil)
	request.Header.Set(AssertionHeader, "signed-token")
	verifier := &fakeVerifier{principal: Principal{Subject: "identity-1", Email: "operator@example.invalid"}}
	principal, err := FromRequest(context.Background(), request, verifier)
	if err != nil {
		t.Fatal(err)
	}
	if verifier.token != "signed-token" || principal.Subject != "identity-1" {
		t.Fatalf("unexpected verification result: %#v", principal)
	}
	verifier.err = errors.New("bad")
	if _, err := FromRequest(context.Background(), request, verifier); err == nil {
		t.Fatal("verifier failure unexpectedly accepted")
	}
}

func TestCloudflareVerifierRejectsNonAccessOrigin(t *testing.T) {
	if _, err := NewCloudflareVerifier(context.Background(), "https://example.com", "audience"); err == nil {
		t.Fatal("non-Cloudflare team domain unexpectedly accepted")
	}
}
