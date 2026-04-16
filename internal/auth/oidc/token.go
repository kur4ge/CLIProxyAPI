package oidc

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/misc"
)

type TokenStorage struct {
	AccessToken   string                            `json:"access_token"`
	RefreshToken  string                            `json:"refresh_token,omitempty"`
	IDToken       string                            `json:"id_token,omitempty"`
	TokenType     string                            `json:"token_type,omitempty"`
	Scope         string                            `json:"scope,omitempty"`
	LastRefresh   string                            `json:"last_refresh,omitempty"`
	Expire        string                            `json:"expired,omitempty"`
	Email         string                            `json:"email,omitempty"`
	Subject       string                            `json:"subject,omitempty"`
	Username      string                            `json:"username,omitempty"`
	Name          string                            `json:"name,omitempty"`
	Issuer        string                            `json:"issuer,omitempty"`
	ClientID      string                            `json:"client_id,omitempty"`
	Domain        string                            `json:"domain,omitempty"`
	AuthorizePath string                            `json:"authorize_path,omitempty"`
	TokenPath     string                            `json:"token_path,omitempty"`
	RedirectURI   string                            `json:"redirect_uri,omitempty"`
	LLMChatURL    string                            `json:"llm_chat_url,omitempty"`
	Headers       map[string]string                 `json:"headers,omitempty"`
	Type          string                            `json:"type"`
	Claims        map[string]any                    `json:"claims,omitempty"`
	Models        []config.OpenAICompatibilityModel `json:"models,omitempty"`
	Metadata      map[string]any                    `json:"-"`
}

func (ts *TokenStorage) SetMetadata(meta map[string]any) {
	ts.Metadata = meta
}

func (ts *TokenStorage) SaveTokenToFile(authFilePath string) error {
	misc.LogSavingCredentials(authFilePath)
	ts.Type = "oidc"
	if err := os.MkdirAll(filepath.Dir(authFilePath), 0o700); err != nil {
		return fmt.Errorf("oidc token: create directory failed: %w", err)
	}
	f, err := os.Create(authFilePath)
	if err != nil {
		return fmt.Errorf("oidc token: create file failed: %w", err)
	}
	defer func() { _ = f.Close() }()
	data, err := misc.MergeMetadata(ts, ts.Metadata)
	if err != nil {
		return fmt.Errorf("oidc token: merge metadata failed: %w", err)
	}
	if err = json.NewEncoder(f).Encode(data); err != nil {
		return fmt.Errorf("oidc token: encode token failed: %w", err)
	}
	return nil
}
