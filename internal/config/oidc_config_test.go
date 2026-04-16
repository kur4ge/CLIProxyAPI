package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigOptional_OIDC(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	configYAML := []byte(`
oidc:
  name: "example"
  domain: "https://sso.example.com"
  authorize-path: "/oauth2/authorize"
  token-path: "/oauth2/token"
  client-id: "client-id"
  scope: "openid profile email"
  callback-path: "/auth/callback"
  redirect-uri: "https://www.example.com/auth/callback"
  llm-chat-url: "https://llm.example.com/v1/chat/completions"
  headers:
    x-test-header: "test-value"
  models:
    - name: "gpt-4.1"
      alias: "gpt-4.1"
`)
	if err := os.WriteFile(configPath, configYAML, 0o600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := LoadConfigOptional(configPath, false)
	if err != nil {
		t.Fatalf("LoadConfigOptional() error = %v", err)
	}

	if len(cfg.OIDC) != 1 {
		t.Fatalf("len(OIDC) = %d, want 1", len(cfg.OIDC))
	}
	if got := cfg.OIDC[0].Name; got != "example" {
		t.Fatalf("OIDC.Name = %q, want %q", got, "example")
	}
	if got := cfg.OIDC[0].Domain; got != "https://sso.example.com" {
		t.Fatalf("OIDC.Domain = %q, want %q", got, "https://sso.example.com")
	}
	if got := cfg.OIDC[0].AuthorizePath; got != "/oauth2/authorize" {
		t.Fatalf("OIDC.AuthorizePath = %q, want %q", got, "/oauth2/authorize")
	}
	if got := cfg.OIDC[0].TokenPath; got != "/oauth2/token" {
		t.Fatalf("OIDC.TokenPath = %q, want %q", got, "/oauth2/token")
	}
	if got := cfg.OIDC[0].ClientID; got != "client-id" {
		t.Fatalf("OIDC.ClientID = %q, want %q", got, "client-id")
	}
	if got := cfg.OIDC[0].Scope; got != "openid profile email" {
		t.Fatalf("OIDC.Scope = %q, want %q", got, "openid profile email")
	}
	if got := cfg.OIDC[0].CallbackPath; got != "/auth/callback" {
		t.Fatalf("OIDC.CallbackPath = %q, want %q", got, "/auth/callback")
	}
	if got := cfg.OIDC[0].RedirectURI; got != "https://www.example.com/auth/callback" {
		t.Fatalf("OIDC.RedirectURI = %q, want %q", got, "https://www.example.com/auth/callback")
	}
	if got := cfg.OIDC[0].LLMChatURL; got != "https://llm.example.com/v1/chat/completions" {
		t.Fatalf("OIDC.LLMChatURL = %q, want %q", got, "https://llm.example.com/v1/chat/completions")
	}
	if got := cfg.OIDC[0].Headers["x-test-header"]; got != "test-value" {
		t.Fatalf("OIDC.Headers[x-test-header] = %q, want %q", got, "test-value")
	}
	if len(cfg.OIDC[0].Models) != 1 || cfg.OIDC[0].Models[0].Alias != "gpt-4.1" {
		t.Fatalf("OIDC.Models = %+v", cfg.OIDC[0].Models)
	}
}

func TestLoadConfigOptional_OIDCMultiple(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	configYAML := []byte(`
- name: "example-1"
  domain: "https://sso.example.com" 
  authorize-path: "/oauth2/authorize"
  token-path: "/oauth2/token"
  client-id: "client-id"
  scope: "openid profile email"
  callback-path: "/auth/callback"
  redirect-uri: "https://www.example.net/auth/callback"
- name: "example-2"
  domain: "https://sso.example.com" 
  authorize-path: "/oauth2/authorize"
  token-path: "/oauth2/token"
  client-id: "client-id"
  scope: "openid profile email"
  callback-path: "/auth/callback"
  redirect-uri: "https://www.example.net/auth/callback"
`)
	if err := os.WriteFile(configPath, configYAML, 0o600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := LoadConfigOptional(configPath, false)
	if err != nil {
		t.Fatalf("LoadConfigOptional() error = %v", err)
	}

	if len(cfg.OIDC) != 2 {
		t.Fatalf("len(OIDC) = %d, want 2", len(cfg.OIDC))
	}
	if got := cfg.OIDC[0].Name; got != "example-1" {
		t.Fatalf("OIDC[0].Name = %q, want %q", got, "example-1")
	}
	if got := cfg.OIDC[1].Name; got != "example-2" {
		t.Fatalf("OIDC[1].Name = %q, want %q", got, "example-2")
	}
}
