package auth

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/auth/oidc"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/browser"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/misc"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/util"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

type OIDCAuthenticator struct {
	CallbackPort int
}

func NewOIDCAuthenticator() *OIDCAuthenticator {
	return &OIDCAuthenticator{CallbackPort: oidc.DefaultCallbackPort}
}

func (a *OIDCAuthenticator) Provider() string {
	return "oidc"
}

func (a *OIDCAuthenticator) RefreshLead() *time.Duration {
	lead := 5 * time.Minute
	return &lead
}

func (a *OIDCAuthenticator) Login(ctx context.Context, cfg *config.Config, opts *LoginOptions) (*coreauth.Auth, error) {
	if cfg == nil {
		return nil, fmt.Errorf("cliproxy auth: configuration is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if opts == nil {
		opts = &LoginOptions{}
	}

	flowConfig, err := oidc.ConfigFromMetadata(opts.Metadata)
	if err != nil {
		return nil, err
	}
	callbackPort := a.CallbackPort
	if opts.CallbackPort > 0 {
		callbackPort = opts.CallbackPort
	}
	redirectURI, err := flowConfig.ResolveRedirectURI(callbackPort)
	if err != nil {
		return nil, err
	}
	bindPort, bindPath, localCallback, err := flowConfig.CallbackBinding(callbackPort)
	if err != nil {
		return nil, err
	}
	pkceCodes, err := oidc.GeneratePKCECodes()
	if err != nil {
		return nil, fmt.Errorf("oidc pkce generation failed: %w", err)
	}
	state, err := misc.GenerateRandomState()
	if err != nil {
		return nil, fmt.Errorf("oidc state generation failed: %w", err)
	}
	authSvc := oidc.NewAuth(cfg, flowConfig)
	authURL, err := authSvc.AuthorizationURL(state, redirectURI, pkceCodes)
	if err != nil {
		return nil, fmt.Errorf("oidc authorization url generation failed: %w", err)
	}

	var oauthServer *oidc.OAuthServer
	if localCallback {
		oauthServer = oidc.NewOAuthServer(bindPort, bindPath)
		if err = oauthServer.Start(); err != nil {
			if strings.Contains(err.Error(), "already in use") || strings.Contains(err.Error(), "bind") || strings.Contains(err.Error(), "listen") {
				return nil, fmt.Errorf("oidc authentication server port in use: %w", err)
			}
			return nil, fmt.Errorf("oidc authentication server failed: %w", err)
		}
		defer func() {
			stopCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if stopErr := oauthServer.Stop(stopCtx); stopErr != nil {
				log.Warnf("oidc oauth server stop error: %v", stopErr)
			}
		}()
	}

	if !opts.NoBrowser {
		fmt.Println("Opening browser for OIDC authentication")
		if !browser.IsAvailable() {
			log.Warn("No browser available; please open the URL manually")
			if localCallback {
				util.PrintSSHTunnelInstructions(bindPort)
			}
			fmt.Printf("Visit the following URL to continue authentication:\n%s\n", authURL)
		} else if err = browser.OpenURL(authURL); err != nil {
			log.Warnf("Failed to open browser automatically: %v", err)
			if localCallback {
				util.PrintSSHTunnelInstructions(bindPort)
			}
			fmt.Printf("Visit the following URL to continue authentication:\n%s\n", authURL)
		}
	} else {
		if localCallback {
			util.PrintSSHTunnelInstructions(bindPort)
		}
		fmt.Printf("Visit the following URL to continue authentication:\n%s\n", authURL)
	}

	fmt.Println("Waiting for OIDC authentication callback...")

	var result *oidc.OAuthResult
	if localCallback {
		result, err = waitForOIDCCallback(oauthServer, opts.Prompt)
	} else {
		if opts.Prompt == nil {
			return nil, fmt.Errorf("oidc redirect uri %s requires manual callback input", redirectURI)
		}
		result, err = waitForManualOIDCCallback(opts.Prompt)
	}
	if err != nil {
		return nil, err
	}
	if result.Error != "" {
		if result.ErrorDescription != "" {
			return nil, fmt.Errorf("oidc authentication failed: %s", result.ErrorDescription)
		}
		return nil, fmt.Errorf("oidc authentication failed: %s", result.Error)
	}
	if result.State != "" && result.State != state {
		return nil, fmt.Errorf("oidc authentication failed: state mismatch")
	}

	tokenData, err := authSvc.ExchangeCodeForTokens(ctx, result.Code, redirectURI, pkceCodes.CodeVerifier)
	if err != nil {
		return nil, fmt.Errorf("oidc token exchange failed: %w", err)
	}
	tokenStorage := authSvc.CreateTokenStorage(tokenData, redirectURI)
	if tokenStorage == nil {
		return nil, fmt.Errorf("oidc token storage could not be created")
	}

	identity := sanitizeFileComponent(firstNonEmpty(tokenStorage.Email, tokenStorage.Username, tokenStorage.Subject, tokenStorage.Name))
	if identity == "" {
		identity = fmt.Sprintf("%d", time.Now().Unix())
	}
	providerName := sanitizeFileComponent(flowConfig.Name)
	if providerName == "" {
		providerName = "oidc"
	}
	fileName := fmt.Sprintf("oidc-%s-%s.json", providerName, identity)
	metadata := map[string]any{
		"type":           "oidc",
		"access_token":   tokenStorage.AccessToken,
		"refresh_token":  tokenStorage.RefreshToken,
		"id_token":       tokenStorage.IDToken,
		"token_type":     tokenStorage.TokenType,
		"scope":          tokenStorage.Scope,
		"expired":        tokenStorage.Expire,
		"email":          tokenStorage.Email,
		"subject":        tokenStorage.Subject,
		"username":       tokenStorage.Username,
		"name":           tokenStorage.Name,
		"issuer":         tokenStorage.Issuer,
		"client_id":      tokenStorage.ClientID,
		"domain":         tokenStorage.Domain,
		"authorize_path": tokenStorage.AuthorizePath,
		"token_path":     tokenStorage.TokenPath,
		"redirect_uri":   tokenStorage.RedirectURI,
		"oidc_name":      flowConfig.Name,
		"llm_chat_url":   tokenStorage.LLMChatURL,
	}
	if len(tokenStorage.Headers) > 0 {
		metadata[oidc.MetadataHeadersKey] = oidc.CloneHeaders(tokenStorage.Headers)
	}
	if len(tokenStorage.Models) > 0 {
		metadata["models"] = tokenStorage.Models
	}
	if len(tokenStorage.Claims) > 0 {
		metadata["claims"] = tokenStorage.Claims
	}

	fmt.Println("OIDC authentication successful")

	auth := &coreauth.Auth{
		ID:       fileName,
		Provider: a.Provider(),
		FileName: fileName,
		Storage:  tokenStorage,
		Metadata: metadata,
		Attributes: map[string]string{
			"issuer":    tokenStorage.Issuer,
			"subject":   tokenStorage.Subject,
			"client_id": tokenStorage.ClientID,
			"oidc_name": flowConfig.Name,
			"chat_url":  tokenStorage.LLMChatURL,
		},
	}
	auth.Attributes = oidc.SyncHeaderAttributes(auth.Attributes, flowConfig.Headers)
	return auth, nil
}

func waitForOIDCCallback(server *oidc.OAuthServer, prompt func(string) (string, error)) (*oidc.OAuthResult, error) {
	callbackCh := make(chan *oidc.OAuthResult, 1)
	callbackErrCh := make(chan error, 1)
	go func() {
		result, err := server.WaitForCallback(5 * time.Minute)
		if err != nil {
			callbackErrCh <- err
			return
		}
		callbackCh <- result
	}()
	var promptTimer *time.Timer
	var promptC <-chan time.Time
	if prompt != nil {
		promptTimer = time.NewTimer(15 * time.Second)
		promptC = promptTimer.C
		defer promptTimer.Stop()
	}
	var manualInputCh <-chan string
	var manualInputErrCh <-chan error
	for {
		select {
		case result := <-callbackCh:
			return result, nil
		case err := <-callbackErrCh:
			return nil, err
		case <-promptC:
			promptC = nil
			if promptTimer != nil {
				promptTimer.Stop()
			}
			select {
			case result := <-callbackCh:
				return result, nil
			case err := <-callbackErrCh:
				return nil, err
			default:
			}
			manualInputCh, manualInputErrCh = misc.AsyncPrompt(prompt, "Paste the OIDC callback URL (or press Enter to keep waiting): ")
		case input := <-manualInputCh:
			manualInputCh = nil
			manualInputErrCh = nil
			parsed, err := misc.ParseOAuthCallback(input)
			if err != nil {
				return nil, err
			}
			if parsed == nil {
				continue
			}
			return &oidc.OAuthResult{
				Code:             parsed.Code,
				State:            parsed.State,
				Error:            parsed.Error,
				ErrorDescription: parsed.ErrorDescription,
			}, nil
		case err := <-manualInputErrCh:
			return nil, err
		}
	}
}

func waitForManualOIDCCallback(prompt func(string) (string, error)) (*oidc.OAuthResult, error) {
	input, err := prompt("Paste the OIDC callback URL: ")
	if err != nil {
		return nil, err
	}
	parsed, err := misc.ParseOAuthCallback(input)
	if err != nil {
		return nil, err
	}
	if parsed == nil {
		return nil, fmt.Errorf("oidc callback url is required")
	}
	return &oidc.OAuthResult{
		Code:             parsed.Code,
		State:            parsed.State,
		Error:            parsed.Error,
		ErrorDescription: parsed.ErrorDescription,
	}, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func sanitizeFileComponent(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	var builder strings.Builder
	for _, r := range raw {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_' || r == '@' {
			builder.WriteRune(r)
			continue
		}
		if r == ' ' || r == '/' || r == '\\' || r == ':' {
			builder.WriteRune('-')
		}
	}
	return strings.Trim(builder.String(), "-")
}
