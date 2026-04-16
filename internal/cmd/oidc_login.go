package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/auth/oidc"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v6/sdk/auth"
)

type OIDCLoginParams struct {
	InitName      string
	Name          string
	Domain        string
	AuthorizePath string
	TokenPath     string
	ClientID      string
	Scope         string
	CallbackPath  string
	RedirectURI   string
	LLMChatURL    string
	Headers       map[string]string
	Models        []config.OpenAICompatibilityModel
}

func DoOIDCLogin(cfg *config.Config, params *OIDCLoginParams, options *LoginOptions) {
	if options == nil {
		options = &LoginOptions{}
	}
	if params == nil {
		params = &OIDCLoginParams{}
	}
	var err error
	params, err = mergeOIDCLoginParams(cfg, params)
	if err != nil {
		fmt.Printf("OIDC authentication failed: %v\n", err)
		return
	}

	promptFn := options.Prompt
	if promptFn == nil {
		promptFn = defaultProjectPrompt()
	}

	manager := newAuthManager()
	modelsJSON := ""
	if len(params.Models) > 0 {
		if encoded, errMarshal := json.Marshal(params.Models); errMarshal == nil {
			modelsJSON = string(encoded)
		}
	}
	headersJSON := ""
	if len(params.Headers) > 0 {
		if encoded, errMarshal := json.Marshal(params.Headers); errMarshal == nil {
			headersJSON = string(encoded)
		}
	}

	authOpts := &sdkAuth.LoginOptions{
		NoBrowser:    options.NoBrowser,
		CallbackPort: options.CallbackPort,
		Prompt:       promptFn,
		Metadata: map[string]string{
			oidc.MetadataNameKey:          params.Name,
			oidc.MetadataDomainKey:        params.Domain,
			oidc.MetadataAuthorizePathKey: params.AuthorizePath,
			oidc.MetadataTokenPathKey:     params.TokenPath,
			oidc.MetadataClientIDKey:      params.ClientID,
			oidc.MetadataScopeKey:         params.Scope,
			oidc.MetadataCallbackPathKey:  params.CallbackPath,
			oidc.MetadataRedirectURIKey:   params.RedirectURI,
			oidc.MetadataLLMChatURLKey:    params.LLMChatURL,
			oidc.MetadataHeadersKey:       headersJSON,
			oidc.MetadataModelsKey:        modelsJSON,
		},
	}

	_, savedPath, err := manager.Login(context.Background(), "oidc", cfg, authOpts)
	if err != nil {
		fmt.Printf("OIDC authentication failed: %v\n", err)
		return
	}

	if savedPath != "" {
		fmt.Printf("Authentication saved to %s\n", savedPath)
	}
	fmt.Println("OIDC authentication successful!")
}

func mergeOIDCLoginParams(cfg *config.Config, params *OIDCLoginParams) (*OIDCLoginParams, error) {
	merged := &OIDCLoginParams{}
	if params != nil {
		merged.InitName = strings.TrimSpace(params.InitName)
	}

	if selected, err := selectOIDCConfig(cfg, merged.InitName); err != nil {
		if !hasExplicitOIDCOverrides(params) {
			return nil, err
		}
	} else if selected != nil {
		merged.Name = strings.TrimSpace(selected.Name)
		merged.Domain = strings.TrimSpace(selected.Domain)
		merged.AuthorizePath = strings.TrimSpace(selected.AuthorizePath)
		merged.TokenPath = strings.TrimSpace(selected.TokenPath)
		merged.ClientID = strings.TrimSpace(selected.ClientID)
		merged.Scope = strings.TrimSpace(selected.Scope)
		merged.CallbackPath = strings.TrimSpace(selected.CallbackPath)
		merged.RedirectURI = strings.TrimSpace(selected.RedirectURI)
		merged.LLMChatURL = strings.TrimSpace(selected.LLMChatURL)
		merged.Headers = oidc.CloneHeaders(selected.Headers)
		merged.Models = append([]config.OpenAICompatibilityModel(nil), selected.Models...)
	}

	if params == nil {
		return merged, nil
	}
	if value := strings.TrimSpace(params.Name); value != "" {
		merged.Name = value
	}
	if value := strings.TrimSpace(params.Domain); value != "" {
		merged.Domain = value
	}
	if value := strings.TrimSpace(params.AuthorizePath); value != "" {
		merged.AuthorizePath = value
	}
	if value := strings.TrimSpace(params.TokenPath); value != "" {
		merged.TokenPath = value
	}
	if value := strings.TrimSpace(params.ClientID); value != "" {
		merged.ClientID = value
	}
	if value := strings.TrimSpace(params.Scope); value != "" {
		merged.Scope = value
	}
	if value := strings.TrimSpace(params.CallbackPath); value != "" {
		merged.CallbackPath = value
	}
	if value := strings.TrimSpace(params.RedirectURI); value != "" {
		merged.RedirectURI = value
	}
	if value := strings.TrimSpace(params.LLMChatURL); value != "" {
		merged.LLMChatURL = value
	}
	return merged, nil
}

func selectOIDCConfig(cfg *config.Config, initName string) (*config.OIDCConfig, error) {
	if cfg == nil || len(cfg.OIDC) == 0 {
		return nil, nil
	}
	if initName != "" {
		for i := range cfg.OIDC {
			candidate := &cfg.OIDC[i]
			if strings.EqualFold(strings.TrimSpace(candidate.Name), initName) {
				return candidate, nil
			}
		}
		return nil, fmt.Errorf("oidc config %q not found", initName)
	}
	if len(cfg.OIDC) == 1 {
		return &cfg.OIDC[0], nil
	}
	return nil, fmt.Errorf("multiple oidc configs found, please specify -oidc-init <name>")
}

func hasExplicitOIDCOverrides(params *OIDCLoginParams) bool {
	if params == nil {
		return false
	}
	return strings.TrimSpace(params.Domain) != "" ||
		strings.TrimSpace(params.AuthorizePath) != "" ||
		strings.TrimSpace(params.TokenPath) != "" ||
		strings.TrimSpace(params.ClientID) != "" ||
		strings.TrimSpace(params.Scope) != "" ||
		strings.TrimSpace(params.CallbackPath) != "" ||
		strings.TrimSpace(params.RedirectURI) != "" ||
		strings.TrimSpace(params.LLMChatURL) != ""
}
