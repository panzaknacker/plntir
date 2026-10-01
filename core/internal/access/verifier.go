package access

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
)

const AssertionHeader = "Cf-Access-Jwt-Assertion"

type Principal struct {
	Subject     string
	Email       string
	CommonName  string
	ServiceAuth bool
}

type Verifier interface {
	Verify(context.Context, string) (Principal, error)
}

type CloudflareVerifier struct {
	verifier *oidc.IDTokenVerifier
}

type claims struct {
	Subject    string `json:"sub"`
	Email      string `json:"email"`
	CommonName string `json:"common_name"`
	Type       string `json:"type"`
}

func NewCloudflareVerifier(ctx context.Context, teamDomain, audience string) (*CloudflareVerifier, error) {
	teamDomain = strings.TrimSuffix(teamDomain, "/")
	parsed, err := url.Parse(teamDomain)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("Cloudflare Access team domain must be an HTTPS origin")
	}
	if !strings.HasSuffix(strings.ToLower(parsed.Hostname()), ".cloudflareaccess.com") {
		return nil, errors.New("Cloudflare Access team domain must end in .cloudflareaccess.com")
	}
	if strings.TrimSpace(audience) == "" || len(audience) > 256 {
		return nil, errors.New("Cloudflare Access audience is required")
	}
	keySet := oidc.NewRemoteKeySet(ctx, teamDomain+"/cdn-cgi/access/certs")
	verifier := oidc.NewVerifier(teamDomain, keySet, &oidc.Config{
		ClientID:             audience,
		SupportedSigningAlgs: []string{oidc.RS256},
	})
	return &CloudflareVerifier{verifier: verifier}, nil
}

func (v *CloudflareVerifier) Verify(ctx context.Context, raw string) (Principal, error) {
	if raw == "" || len(raw) > 16<<10 {
		return Principal{}, errors.New("missing or oversized Cloudflare Access assertion")
	}
	token, err := v.verifier.Verify(ctx, raw)
	if err != nil {
		return Principal{}, errors.New("invalid Cloudflare Access assertion")
	}
	var value claims
	if err := token.Claims(&value); err != nil {
		return Principal{}, errors.New("invalid Cloudflare Access claims")
	}
	if value.Type != "app" {
		return Principal{}, fmt.Errorf("unexpected Cloudflare Access token type")
	}
	service := value.Subject == "" && value.CommonName != ""
	if !service && (value.Subject == "" || value.Email == "") {
		return Principal{}, errors.New("Cloudflare Access identity token lacks subject or email")
	}
	return Principal{
		Subject: value.Subject, Email: value.Email, CommonName: value.CommonName, ServiceAuth: service,
	}, nil
}

func FromRequest(ctx context.Context, request *http.Request, verifier Verifier) (Principal, error) {
	if verifier == nil {
		return Principal{}, errors.New("Access verifier is not configured")
	}
	return verifier.Verify(ctx, request.Header.Get(AssertionHeader))
}
