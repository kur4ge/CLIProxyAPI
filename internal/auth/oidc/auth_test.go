package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
)

func TestConfigFromMetadata(t *testing.T) {
	cfg, err := ConfigFromMetadata(map[string]string{
		MetadataDomainKey:        "sso.example.com",
		MetadataAuthorizePathKey: "oauth2/authorize",
		MetadataTokenPathKey:     "/oauth2/token",
		MetadataClientIDKey:      "client-id",
		MetadataHeadersKey:       `{"X-Test":" value ","X-Empty":"   "}`,
	})
	if err != nil {
		t.Fatalf("ConfigFromMetadata() error = %v", err)
	}
	if cfg.Domain != "https://sso.example.com" {
		t.Fatalf("Domain = %q", cfg.Domain)
	}
	if cfg.AuthorizePath != "/oauth2/authorize" {
		t.Fatalf("AuthorizePath = %q", cfg.AuthorizePath)
	}
	if cfg.TokenPath != "/oauth2/token" {
		t.Fatalf("TokenPath = %q", cfg.TokenPath)
	}
	if cfg.Scope != DefaultScope {
		t.Fatalf("Scope = %q", cfg.Scope)
	}
	if cfg.CallbackPath != DefaultCallbackPath {
		t.Fatalf("CallbackPath = %q", cfg.CallbackPath)
	}
	if got := cfg.Headers["X-Test"]; got != "value" {
		t.Fatalf("Headers[X-Test] = %q", got)
	}
	if _, ok := cfg.Headers["X-Empty"]; ok {
		t.Fatalf("Headers unexpectedly contains X-Empty")
	}
}

func TestSyncHeaderAttributes(t *testing.T) {
	attrs := SyncHeaderAttributes(map[string]string{
		"keep":         "1",
		"header:X-Old": "old",
	}, map[string]string{
		" X-Test ": " value ",
	})
	if got := attrs["header:X-Test"]; got != "value" {
		t.Fatalf("header:X-Test = %q", got)
	}
	if _, ok := attrs["header:X-Old"]; ok {
		t.Fatalf("expected header:X-Old to be removed")
	}
	if got := attrs["keep"]; got != "1" {
		t.Fatalf("keep = %q", got)
	}
}

func TestAuthorizationURL(t *testing.T) {
	auth := NewAuth(&config.Config{}, FlowConfig{
		Domain:        "https://sso.example.com",
		AuthorizePath: "/oauth2/authorize",
		TokenPath:     "/oauth2/token",
		ClientID:      "client-id",
		Scope:         "openid profile email",
	})
	pkce := &PKCECodes{
		CodeVerifier:  "verifier",
		CodeChallenge: "challenge",
	}
	redirectURI := "https://www.example.net/auth/callback"
	authURL, err := auth.AuthorizationURL("state-123", redirectURI, pkce)
	if err != nil {
		t.Fatalf("AuthorizationURL() error = %v", err)
	}
	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}
	if parsed.Host != "sso.example.com" {
		t.Fatalf("host = %q", parsed.Host)
	}
	if parsed.Path != "/oauth2/authorize" {
		t.Fatalf("path = %q", parsed.Path)
	}
	query := parsed.Query()
	if query.Get("client_id") != "client-id" {
		t.Fatalf("client_id = %q", query.Get("client_id"))
	}
	if query.Get("redirect_uri") != redirectURI {
		t.Fatalf("redirect_uri = %q", query.Get("redirect_uri"))
	}
	if query.Get("code_challenge") != "challenge" {
		t.Fatalf("code_challenge = %q", query.Get("code_challenge"))
	}
}

func TestExchangeAndRefreshTokens(t *testing.T) {
	var requests []url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth2/token" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm() error = %v", err)
		}
		requests = append(requests, r.Form)
		w.Header().Set("Content-Type", "application/json")
		switch r.Form.Get("grant_type") {
		case "authorization_code":
			_, _ = w.Write([]byte(`{"access_token":"access-1","token_type":"Bearer","expires_in":3600,"refresh_token":"refresh-1","id_token":"` + testJWT(map[string]any{
				"email":    "tester@example.com",
				"sub":      "subject-1",
				"username": "tester",
				"name":     "Tester",
				"iss":      "https://sso.example.com",
			}) + `","scope":"openid profile email"}`))
		case "refresh_token":
			_, _ = w.Write([]byte(`{"access_token":"access-2","token_type":"Bearer","expires_in":3600,"refresh_token":"refresh-2","id_token":"` + testJWT(map[string]any{
				"email": "tester@example.com",
				"sub":   "subject-1",
				"iss":   "https://sso.example.com",
			}) + `","scope":"openid profile email"}`))
		default:
			t.Fatalf("unexpected grant_type %q", r.Form.Get("grant_type"))
		}
	}))
	defer server.Close()

	auth := NewAuth(&config.Config{}, FlowConfig{
		Domain:        server.URL,
		AuthorizePath: "/oauth2/authorize",
		TokenPath:     "/oauth2/token",
		ClientID:      "client-id",
		Scope:         "openid profile email",
	})

	redirectURI := "https://www.example.net/auth/callback"
	tokenData, err := auth.ExchangeCodeForTokens(context.Background(), "code-1", redirectURI, "verifier-1")
	if err != nil {
		t.Fatalf("ExchangeCodeForTokens() error = %v", err)
	}
	if tokenData.AccessToken != "access-1" {
		t.Fatalf("AccessToken = %q", tokenData.AccessToken)
	}
	if tokenData.RefreshToken != "refresh-1" {
		t.Fatalf("RefreshToken = %q", tokenData.RefreshToken)
	}
	if tokenData.Email != "tester@example.com" {
		t.Fatalf("Email = %q", tokenData.Email)
	}
	if tokenData.Subject != "subject-1" {
		t.Fatalf("Subject = %q", tokenData.Subject)
	}
	if tokenData.Issuer != "https://sso.example.com" {
		t.Fatalf("Issuer = %q", tokenData.Issuer)
	}

	refreshed, err := auth.RefreshTokens(context.Background(), "refresh-1")
	if err != nil {
		t.Fatalf("RefreshTokens() error = %v", err)
	}
	if refreshed.AccessToken != "access-2" {
		t.Fatalf("refreshed AccessToken = %q", refreshed.AccessToken)
	}
	if refreshed.RefreshToken != "refresh-2" {
		t.Fatalf("refreshed RefreshToken = %q", refreshed.RefreshToken)
	}
	if len(requests) != 2 {
		t.Fatalf("request count = %d", len(requests))
	}
	if got := requests[0].Get("redirect_uri"); got != redirectURI {
		t.Fatalf("authorization redirect_uri = %q", got)
	}
	if got := requests[0].Get("code_verifier"); got != "verifier-1" {
		t.Fatalf("authorization code_verifier = %q", got)
	}
	if got := requests[1].Get("refresh_token"); got != "refresh-1" {
		t.Fatalf("refresh refresh_token = %q", got)
	}
}

func testJWT(claims map[string]any) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payloadBytes, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	return strings.Join([]string{header, payload, "signature"}, ".")
}
