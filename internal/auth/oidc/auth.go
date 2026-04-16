package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/util"
)

const (
	DefaultCallbackPath = "/auth/callback"
	DefaultScope        = "openid profile email"
	DefaultCallbackPort = 38965
)

const (
	MetadataDomainKey        = "domain"
	MetadataAuthorizePathKey = "authorize_path"
	MetadataAuthPathKey      = "auth_path"
	MetadataTokenPathKey     = "token_path"
	MetadataClientIDKey      = "client_id"
	MetadataScopeKey         = "scope"
	MetadataCallbackPathKey  = "callback_path"
	MetadataRedirectURIKey   = "redirect_uri"
	MetadataNameKey          = "oidc_name"
	MetadataLLMChatURLKey    = "llm_chat_url"
	MetadataHeadersKey       = "headers"
	MetadataModelsKey        = "models"
)

type FlowConfig struct {
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

type Auth struct {
	httpClient *http.Client
	config     FlowConfig
}

type TokenData struct {
	AccessToken  string
	RefreshToken string
	IDToken      string
	TokenType    string
	Scope        string
	Email        string
	Subject      string
	Username     string
	Name         string
	Issuer       string
	Expire       string
	Claims       map[string]any
}

func ConfigFromMetadata(metadata map[string]string) (FlowConfig, error) {
	cfg := FlowConfig{
		Domain:        stringMetadata(metadata, MetadataDomainKey),
		AuthorizePath: stringMetadata(metadata, MetadataAuthorizePathKey),
		TokenPath:     stringMetadata(metadata, MetadataTokenPathKey),
		ClientID:      stringMetadata(metadata, MetadataClientIDKey),
		Scope:         stringMetadata(metadata, MetadataScopeKey),
		CallbackPath:  stringMetadata(metadata, MetadataCallbackPathKey),
		RedirectURI:   stringMetadata(metadata, MetadataRedirectURIKey),
		Name:          stringMetadata(metadata, MetadataNameKey),
		LLMChatURL:    stringMetadata(metadata, MetadataLLMChatURLKey),
	}
	headers, err := parseHeadersMetadata(metadata)
	if err != nil {
		return FlowConfig{}, err
	}
	cfg.Headers = headers
	if cfg.AuthorizePath == "" {
		cfg.AuthorizePath = stringMetadata(metadata, MetadataAuthPathKey)
	}
	if cfg.Scope == "" {
		cfg.Scope = DefaultScope
	}
	if cfg.CallbackPath == "" {
		cfg.CallbackPath = DefaultCallbackPath
	}
	if cfg.Domain == "" {
		return FlowConfig{}, fmt.Errorf("oidc domain is required")
	}
	if cfg.AuthorizePath == "" {
		return FlowConfig{}, fmt.Errorf("oidc authorize path is required")
	}
	if cfg.TokenPath == "" {
		return FlowConfig{}, fmt.Errorf("oidc token path is required")
	}
	if cfg.ClientID == "" {
		return FlowConfig{}, fmt.Errorf("oidc client_id is required")
	}
	normalizedDomain, err := normalizeDomain(cfg.Domain)
	if err != nil {
		return FlowConfig{}, err
	}
	cfg.Domain = normalizedDomain
	cfg.AuthorizePath = normalizeURLPath(cfg.AuthorizePath)
	cfg.TokenPath = normalizeURLPath(cfg.TokenPath)
	cfg.CallbackPath = normalizeURLPath(cfg.CallbackPath)
	if cfg.RedirectURI != "" {
		cfg.RedirectURI = strings.TrimSpace(cfg.RedirectURI)
		if _, err = url.Parse(cfg.RedirectURI); err != nil {
			return FlowConfig{}, fmt.Errorf("invalid oidc redirect uri: %w", err)
		}
	}
	if cfg.LLMChatURL != "" {
		cfg.LLMChatURL = strings.TrimSpace(cfg.LLMChatURL)
		if _, err = url.Parse(cfg.LLMChatURL); err != nil {
			return FlowConfig{}, fmt.Errorf("invalid oidc llm chat url: %w", err)
		}
	}
	if cfg.Name == "" {
		if parsed, errParse := url.Parse(cfg.Domain); errParse == nil && parsed.Hostname() != "" {
			cfg.Name = parsed.Hostname()
		}
	}
	if cfg.Name == "" {
		cfg.Name = "oidc"
	}
	if modelsRaw := stringMetadata(metadata, MetadataModelsKey); modelsRaw != "" {
		var models []config.OpenAICompatibilityModel
		if err = json.Unmarshal([]byte(modelsRaw), &models); err != nil {
			return FlowConfig{}, fmt.Errorf("invalid oidc models: %w", err)
		}
		cfg.Models = models
	}
	return cfg, nil
}

func NewAuth(cfg *config.Config, flowConfig FlowConfig) *Auth {
	client := &http.Client{Timeout: 30 * time.Second}
	if cfg == nil {
		return &Auth{httpClient: client, config: flowConfig}
	}
	return &Auth{
		httpClient: util.SetProxy(&cfg.SDKConfig, client),
		config:     flowConfig,
	}
}

func (a *Auth) AuthorizationURL(state, redirectURI string, pkce *PKCECodes) (string, error) {
	if a == nil {
		return "", fmt.Errorf("oidc auth is nil")
	}
	if pkce == nil {
		return "", fmt.Errorf("pkce codes are required")
	}
	redirectURI = strings.TrimSpace(redirectURI)
	if redirectURI == "" {
		return "", fmt.Errorf("redirect uri is required")
	}
	values := url.Values{}
	values.Set("response_type", "code")
	values.Set("client_id", a.config.ClientID)
	values.Set("redirect_uri", redirectURI)
	values.Set("scope", a.config.Scope)
	values.Set("state", state)
	values.Set("code_challenge", pkce.CodeChallenge)
	values.Set("code_challenge_method", "S256")
	return joinURL(a.config.Domain, a.config.AuthorizePath) + "?" + values.Encode(), nil
}

func (a *Auth) ExchangeCodeForTokens(ctx context.Context, code, redirectURI, codeVerifier string) (*TokenData, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", a.config.ClientID)
	form.Set("code", strings.TrimSpace(code))
	form.Set("redirect_uri", strings.TrimSpace(redirectURI))
	form.Set("code_verifier", strings.TrimSpace(codeVerifier))
	return a.tokenRequest(ctx, form)
}

func (a *Auth) RefreshTokens(ctx context.Context, refreshToken string) (*TokenData, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("client_id", a.config.ClientID)
	form.Set("refresh_token", strings.TrimSpace(refreshToken))
	return a.tokenRequest(ctx, form)
}

func (a *Auth) CreateTokenStorage(data *TokenData, redirectURI string) *TokenStorage {
	if data == nil {
		return nil
	}
	return &TokenStorage{
		AccessToken:   data.AccessToken,
		RefreshToken:  data.RefreshToken,
		IDToken:       data.IDToken,
		TokenType:     data.TokenType,
		Scope:         data.Scope,
		LastRefresh:   time.Now().UTC().Format(time.RFC3339),
		Expire:        data.Expire,
		Email:         data.Email,
		Subject:       data.Subject,
		Username:      data.Username,
		Name:          data.Name,
		Issuer:        data.Issuer,
		ClientID:      a.config.ClientID,
		Domain:        a.config.Domain,
		AuthorizePath: a.config.AuthorizePath,
		TokenPath:     a.config.TokenPath,
		RedirectURI:   strings.TrimSpace(redirectURI),
		LLMChatURL:    a.config.LLMChatURL,
		Headers:       CloneHeaders(a.config.Headers),
		Type:          "oidc",
		Claims:        cloneMap(data.Claims),
		Models:        cloneModels(a.config.Models),
	}
}

func SyncHeaderAttributes(attrs map[string]string, headers map[string]string) map[string]string {
	if attrs == nil {
		attrs = make(map[string]string)
	}
	for key := range attrs {
		if strings.HasPrefix(key, "header:") {
			delete(attrs, key)
		}
	}
	for name, value := range normalizeHeaders(headers) {
		attrs["header:"+name] = value
	}
	return attrs
}

func parseHeadersMetadata(metadata map[string]string) (map[string]string, error) {
	raw := strings.TrimSpace(metadata[MetadataHeadersKey])
	if raw == "" {
		return nil, nil
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		return nil, fmt.Errorf("invalid oidc headers: %w", err)
	}
	headers := make(map[string]string, len(decoded))
	for key, value := range decoded {
		name := strings.TrimSpace(key)
		if name == "" {
			continue
		}
		rawValue, ok := value.(string)
		if !ok {
			continue
		}
		trimmedValue := strings.TrimSpace(rawValue)
		if trimmedValue == "" {
			continue
		}
		headers[name] = trimmedValue
	}
	if len(headers) == 0 {
		return nil, nil
	}
	return headers, nil
}

func CloneHeaders(headers map[string]string) map[string]string {
	if len(headers) == 0 {
		return nil
	}
	cloned := make(map[string]string, len(headers))
	for key, value := range normalizeHeaders(headers) {
		cloned[key] = value
	}
	if len(cloned) == 0 {
		return nil
	}
	return cloned
}

func normalizeHeaders(headers map[string]string) map[string]string {
	if len(headers) == 0 {
		return nil
	}
	normalized := make(map[string]string, len(headers))
	for key, value := range headers {
		name := strings.TrimSpace(key)
		if name == "" {
			continue
		}
		trimmedValue := strings.TrimSpace(value)
		if trimmedValue == "" {
			continue
		}
		normalized[name] = trimmedValue
	}
	if len(normalized) == 0 {
		return nil
	}
	return normalized
}

func (c FlowConfig) ResolveRedirectURI(port int) (string, error) {
	if strings.TrimSpace(c.RedirectURI) != "" {
		return strings.TrimSpace(c.RedirectURI), nil
	}
	if port <= 0 {
		port = DefaultCallbackPort
	}
	return fmt.Sprintf("http://localhost:%d%s", port, normalizeURLPath(c.CallbackPath)), nil
}

func (c FlowConfig) CallbackBinding(defaultPort int) (int, string, bool, error) {
	redirectURI, err := c.ResolveRedirectURI(defaultPort)
	if err != nil {
		return 0, "", false, err
	}
	parsed, err := url.Parse(redirectURI)
	if err != nil {
		return 0, "", false, fmt.Errorf("invalid redirect uri: %w", err)
	}
	host := strings.ToLower(parsed.Hostname())
	if host != "localhost" && host != "127.0.0.1" {
		return 0, normalizeURLPath(parsed.Path), false, nil
	}
	port := parsed.Port()
	if port == "" {
		switch parsed.Scheme {
		case "https":
			port = "443"
		default:
			port = "80"
		}
	}
	parsedPort, err := strconv.Atoi(port)
	if err != nil {
		return 0, "", false, fmt.Errorf("invalid redirect uri port: %w", err)
	}
	return parsedPort, normalizeURLPath(parsed.Path), true, nil
}

func (a *Auth) tokenRequest(ctx context.Context, form url.Values) (*TokenData, error) {
	if a == nil {
		return nil, fmt.Errorf("oidc auth is nil")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, joinURL(a.config.Domain, a.config.TokenPath), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("oidc token: create request failed: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc token: request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("oidc token: read response failed: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc token: unexpected status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		Scope        string `json:"scope"`
	}
	if err = json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("oidc token: parse response failed: %w", err)
	}
	data := &TokenData{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		IDToken:      tokenResp.IDToken,
		TokenType:    tokenResp.TokenType,
		Scope:        tokenResp.Scope,
	}
	if tokenResp.ExpiresIn > 0 {
		data.Expire = time.Now().UTC().Add(time.Duration(tokenResp.ExpiresIn) * time.Second).Format(time.RFC3339)
	}
	claims, err := parseIDTokenClaims(tokenResp.IDToken)
	if err == nil && claims != nil {
		data.Claims = claims.Raw
		data.Email = claims.Email
		data.Subject = claims.Subject
		data.Username = claims.Username
		data.Name = claims.Name
		data.Issuer = claims.Issuer
	}
	return data, nil
}

type idTokenClaims struct {
	Raw      map[string]any
	Email    string
	Subject  string
	Username string
	Name     string
	Issuer   string
}

func parseIDTokenClaims(token string) (*idTokenClaims, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, nil
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid id_token format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		payload, err = base64.URLEncoding.DecodeString(addBase64Padding(parts[1]))
		if err != nil {
			return nil, fmt.Errorf("decode id_token payload failed: %w", err)
		}
	}
	raw := make(map[string]any)
	if err = json.Unmarshal(payload, &raw); err != nil {
		return nil, fmt.Errorf("parse id_token payload failed: %w", err)
	}
	return &idTokenClaims{
		Raw:      raw,
		Email:    firstString(raw, "email", "upn"),
		Subject:  firstString(raw, "sub"),
		Username: firstString(raw, "preferred_username", "username", "login"),
		Name:     firstString(raw, "name", "given_name"),
		Issuer:   firstString(raw, "iss"),
	}, nil
}

func stringMetadata(metadata map[string]string, key string) string {
	if metadata == nil {
		return ""
	}
	return strings.TrimSpace(metadata[key])
}

func normalizeDomain(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("oidc domain is empty")
	}
	if !strings.Contains(trimmed, "://") {
		trimmed = "https://" + trimmed
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("invalid oidc domain: %w", err)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("invalid oidc domain")
	}
	parsed.Path = ""
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return strings.TrimRight(parsed.String(), "/"), nil
}

func normalizeURLPath(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "/"
	}
	if !strings.HasPrefix(trimmed, "/") {
		trimmed = "/" + trimmed
	}
	return trimmed
}

func joinURL(domain, path string) string {
	return strings.TrimRight(domain, "/") + normalizeURLPath(path)
}

func firstString(raw map[string]any, keys ...string) string {
	for _, key := range keys {
		value, ok := raw[key]
		if !ok {
			continue
		}
		text, ok := value.(string)
		if ok && strings.TrimSpace(text) != "" {
			return strings.TrimSpace(text)
		}
	}
	return ""
}

func addBase64Padding(value string) string {
	switch len(value) % 4 {
	case 2:
		return value + "=="
	case 3:
		return value + "="
	default:
		return value
	}
}

func cloneMap(input map[string]any) map[string]any {
	if len(input) == 0 {
		return nil
	}
	output := make(map[string]any, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func cloneModels(input []config.OpenAICompatibilityModel) []config.OpenAICompatibilityModel {
	if len(input) == 0 {
		return nil
	}
	output := make([]config.OpenAICompatibilityModel, len(input))
	copy(output, input)
	return output
}

func IsLoopbackHost(raw string) bool {
	host := strings.ToLower(strings.TrimSpace(raw))
	if host == "localhost" || host == "127.0.0.1" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
