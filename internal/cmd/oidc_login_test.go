package cmd

import (
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
)

func TestMergeOIDCLoginParams_SelectByInitName(t *testing.T) {
	cfg := &config.Config{
		OIDC: config.OIDCConfigs{
			{
				Name:          "example-1",
				Domain:        "https://sso.example.com",
				AuthorizePath: "/oauth2/authorize",
				TokenPath:     "/oauth2/token",
				ClientID:      "client-1",
			},
			{
				Name:          "example-2",
				Domain:        "https://sso.example.com",
				AuthorizePath: "/authorize",
				TokenPath:     "/token",
				ClientID:      "client-2",
				Headers: map[string]string{
					"X-Test": "value",
				},
			},
		},
	}

	params, err := mergeOIDCLoginParams(cfg, &OIDCLoginParams{InitName: "example-2"})
	if err != nil {
		t.Fatalf("mergeOIDCLoginParams() error = %v", err)
	}
	if got := params.Name; got != "example-2" {
		t.Fatalf("Name = %q, want %q", got, "example-2")
	}
	if got := params.Domain; got != "https://sso.example.com" {
		t.Fatalf("Domain = %q, want %q", got, "https://sso.example.com")
	}
	if got := params.ClientID; got != "client-2" {
		t.Fatalf("ClientID = %q, want %q", got, "client-2")
	}
	if got := params.Headers["X-Test"]; got != "value" {
		t.Fatalf("Headers[X-Test] = %q, want %q", got, "value")
	}
}

func TestMergeOIDCLoginParams_MultipleRequiresInitName(t *testing.T) {
	cfg := &config.Config{
		OIDC: config.OIDCConfigs{
			{Name: "example-1", Domain: "https://sso.example.com"},
			{Name: "example-2", Domain: "https://sso.example.com"},
		},
	}

	_, err := mergeOIDCLoginParams(cfg, &OIDCLoginParams{})
	if err == nil {
		t.Fatal("expected error when multiple oidc configs exist without init name")
	}
}
