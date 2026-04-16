package executor

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	oidcauth "github.com/router-for-me/CLIProxyAPI/v6/internal/auth/oidc"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/runtime/executor/helps"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/thinking"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/util"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v6/sdk/translator"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/sjson"
)

type OIDCExecutor struct {
	cfg *config.Config
}

func NewOIDCExecutor(cfg *config.Config) *OIDCExecutor {
	return &OIDCExecutor{cfg: cfg}
}

func (e *OIDCExecutor) Identifier() string { return "oidc" }

func (e *OIDCExecutor) PrepareRequest(req *http.Request, auth *cliproxyauth.Auth) error {
	if req == nil {
		return nil
	}
	if token := e.resolveBearerToken(auth); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if auth != nil {
		util.ApplyCustomHeadersFromAttrs(req, auth.Attributes)
	}
	return nil
}

func (e *OIDCExecutor) HttpRequest(ctx context.Context, auth *cliproxyauth.Auth, req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, fmt.Errorf("oidc executor: request is nil")
	}
	if ctx == nil {
		ctx = req.Context()
	}
	httpReq := req.WithContext(ctx)
	if err := e.PrepareRequest(httpReq, auth); err != nil {
		return nil, err
	}
	httpClient := helps.NewProxyAwareHTTPClient(ctx, e.cfg, auth, 0)
	return httpClient.Do(httpReq)
}

func (e *OIDCExecutor) Execute(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (resp cliproxyexecutor.Response, err error) {
	if isOIDCEmbeddingRequest(opts) {
		return e.executeEmbeddings(ctx, auth, req, opts)
	}
	if opts.Alt == "responses/compact" {
		return resp, statusErr{code: http.StatusBadRequest, msg: "oidc executor: responses API is not supported; use /v1/chat/completions"}
	}

	baseModel := thinking.ParseSuffix(req.Model).ModelName
	reporter := helps.NewUsageReporter(ctx, e.Identifier(), baseModel, auth)
	defer reporter.TrackFailure(ctx, &err)

	chatURL := e.resolveChatURL(auth)
	if chatURL == "" {
		err = statusErr{code: http.StatusUnauthorized, msg: "missing oidc llm chat url"}
		return
	}

	jwt := e.resolveBearerToken(auth)
	if jwt == "" {
		err = statusErr{code: http.StatusUnauthorized, msg: "missing oidc jwt"}
		return
	}

	from := opts.SourceFormat
	to := oidcTargetFormat(chatURL)
	originalPayloadSource := req.Payload
	if len(opts.OriginalRequest) > 0 {
		originalPayloadSource = opts.OriginalRequest
	}
	originalTranslated := sdktranslator.TranslateRequest(from, to, baseModel, originalPayloadSource, opts.Stream)
	translated := sdktranslator.TranslateRequest(from, to, baseModel, req.Payload, opts.Stream)
	requestedModel := helps.PayloadRequestedModel(opts, req.Model)
	translated = helps.ApplyPayloadConfigWithRoot(e.cfg, baseModel, to.String(), "", translated, originalTranslated, requestedModel)
	translated, err = thinking.ApplyThinking(translated, req.Model, from.String(), to.String(), e.Identifier())
	if err != nil {
		return resp, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, chatURL, bytes.NewReader(translated))
	if err != nil {
		return resp, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+jwt)
	httpReq.Header.Set("User-Agent", "cli-proxy-oidc")
	if auth != nil {
		util.ApplyCustomHeadersFromAttrs(httpReq, auth.Attributes)
	}

	e.recordRequest(ctx, auth, chatURL, translated)
	httpClient := helps.NewProxyAwareHTTPClient(ctx, e.cfg, auth, 0)
	httpResp, err := httpClient.Do(httpReq)
	if err != nil {
		helps.RecordAPIResponseError(ctx, e.cfg, err)
		return resp, err
	}
	defer func() {
		if errClose := httpResp.Body.Close(); errClose != nil {
			log.Errorf("oidc executor: close response body error: %v", errClose)
		}
	}()
	helps.RecordAPIResponseMetadata(ctx, e.cfg, httpResp.StatusCode, httpResp.Header.Clone())
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		b, _ := io.ReadAll(httpResp.Body)
		helps.AppendAPIResponseChunk(ctx, e.cfg, b)
		err = statusErr{code: httpResp.StatusCode, msg: string(b)}
		return resp, err
	}
	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		helps.RecordAPIResponseError(ctx, e.cfg, err)
		return resp, err
	}
	helps.AppendAPIResponseChunk(ctx, e.cfg, body)
	reporter.Publish(ctx, helps.ParseOpenAIUsage(body))
	reporter.EnsurePublished(ctx)

	var param any
	out := sdktranslator.TranslateNonStream(ctx, to, from, req.Model, opts.OriginalRequest, translated, body, &param)
	return cliproxyexecutor.Response{Payload: out, Headers: httpResp.Header.Clone()}, nil
}

func (e *OIDCExecutor) ExecuteStream(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (_ *cliproxyexecutor.StreamResult, err error) {
	if isOIDCEmbeddingRequest(opts) {
		return nil, statusErr{code: http.StatusBadRequest, msg: "oidc executor: embeddings endpoint does not support streaming"}
	}
	if opts.Alt == "responses/compact" {
		return nil, statusErr{code: http.StatusBadRequest, msg: "oidc executor: responses API is not supported; use /v1/chat/completions"}
	}

	baseModel := thinking.ParseSuffix(req.Model).ModelName
	reporter := helps.NewUsageReporter(ctx, e.Identifier(), baseModel, auth)
	defer reporter.TrackFailure(ctx, &err)

	chatURL := e.resolveChatURL(auth)
	if chatURL == "" {
		err = statusErr{code: http.StatusUnauthorized, msg: "missing oidc llm chat url"}
		return nil, err
	}
	jwt := e.resolveBearerToken(auth)
	if jwt == "" {
		err = statusErr{code: http.StatusUnauthorized, msg: "missing oidc jwt"}
		return nil, err
	}

	from := opts.SourceFormat
	to := oidcTargetFormat(chatURL)
	originalPayloadSource := req.Payload
	if len(opts.OriginalRequest) > 0 {
		originalPayloadSource = opts.OriginalRequest
	}
	originalTranslated := sdktranslator.TranslateRequest(from, to, baseModel, originalPayloadSource, true)
	translated := sdktranslator.TranslateRequest(from, to, baseModel, req.Payload, true)
	requestedModel := helps.PayloadRequestedModel(opts, req.Model)
	translated = helps.ApplyPayloadConfigWithRoot(e.cfg, baseModel, to.String(), "", translated, originalTranslated, requestedModel)
	translated, err = thinking.ApplyThinking(translated, req.Model, from.String(), to.String(), e.Identifier())
	if err != nil {
		return nil, err
	}
	translated, _ = sjson.SetBytes(translated, "stream_options.include_usage", true)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, chatURL, bytes.NewReader(translated))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+jwt)
	httpReq.Header.Set("Accept", "text/event-stream")
	if auth != nil {
		util.ApplyCustomHeadersFromAttrs(httpReq, auth.Attributes)
	}

	e.recordRequest(ctx, auth, chatURL, translated)
	httpClient := helps.NewProxyAwareHTTPClient(ctx, e.cfg, auth, 0)
	httpResp, err := httpClient.Do(httpReq)
	if err != nil {
		helps.RecordAPIResponseError(ctx, e.cfg, err)
		return nil, err
	}
	helps.RecordAPIResponseMetadata(ctx, e.cfg, httpResp.StatusCode, httpResp.Header.Clone())
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		b, _ := io.ReadAll(httpResp.Body)
		helps.AppendAPIResponseChunk(ctx, e.cfg, b)
		if errClose := httpResp.Body.Close(); errClose != nil {
			log.Errorf("oidc executor: close response body error: %v", errClose)
		}
		return nil, statusErr{code: httpResp.StatusCode, msg: string(b)}
	}

	out := make(chan cliproxyexecutor.StreamChunk)
	go func() {
		defer close(out)
		defer func() {
			if errClose := httpResp.Body.Close(); errClose != nil {
				log.Errorf("oidc executor: close response body error: %v", errClose)
			}
		}()
		scanner := bufio.NewScanner(httpResp.Body)
		scanner.Buffer(nil, 52_428_800)
		var param any
		for scanner.Scan() {
			line := scanner.Bytes()
			helps.AppendAPIResponseChunk(ctx, e.cfg, line)
			if detail, ok := helps.ParseOpenAIStreamUsage(line); ok {
				reporter.Publish(ctx, detail)
			}
			if len(line) == 0 || !bytes.HasPrefix(line, []byte("data:")) {
				continue
			}
			chunks := sdktranslator.TranslateStream(ctx, to, from, req.Model, opts.OriginalRequest, translated, bytes.Clone(line), &param)
			for i := range chunks {
				out <- cliproxyexecutor.StreamChunk{Payload: chunks[i]}
			}
		}
		if errScan := scanner.Err(); errScan != nil {
			helps.RecordAPIResponseError(ctx, e.cfg, errScan)
			reporter.PublishFailure(ctx)
			out <- cliproxyexecutor.StreamChunk{Err: errScan}
		}
		reporter.EnsurePublished(ctx)
	}()
	return &cliproxyexecutor.StreamResult{Headers: httpResp.Header.Clone(), Chunks: out}, nil
}

func (e *OIDCExecutor) CountTokens(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	if isOIDCEmbeddingRequest(opts) {
		return cliproxyexecutor.Response{}, fmt.Errorf("oidc executor: token counting for embeddings is not supported")
	}
	baseModel := thinking.ParseSuffix(req.Model).ModelName
	from := opts.SourceFormat
	to := sdktranslator.FromString("openai")
	translated := sdktranslator.TranslateRequest(from, to, baseModel, req.Payload, false)
	translated, err := thinking.ApplyThinking(translated, req.Model, from.String(), to.String(), e.Identifier())
	if err != nil {
		return cliproxyexecutor.Response{}, err
	}
	enc, err := helps.TokenizerForModel(baseModel)
	if err != nil {
		return cliproxyexecutor.Response{}, fmt.Errorf("oidc executor: tokenizer init failed: %w", err)
	}
	count, err := helps.CountOpenAIChatTokens(enc, translated)
	if err != nil {
		return cliproxyexecutor.Response{}, fmt.Errorf("oidc executor: token counting failed: %w", err)
	}
	usageJSON := helps.BuildOpenAIUsageJSON(count)
	translatedUsage := sdktranslator.TranslateTokenCount(ctx, to, from, count, usageJSON)
	return cliproxyexecutor.Response{Payload: translatedUsage}, nil
}

func (e *OIDCExecutor) Refresh(ctx context.Context, auth *cliproxyauth.Auth) (*cliproxyauth.Auth, error) {
	if auth == nil {
		return nil, fmt.Errorf("oidc executor: auth is nil")
	}
	metadataMap := metadataStringMap(auth.Metadata)
	flowConfig, err := oidcauth.ConfigFromMetadata(metadataMap)
	if err != nil {
		return nil, err
	}
	refreshToken := metadataNestedStringValue(auth.Metadata, "refresh_token")
	if refreshToken == "" {
		return auth, nil
	}
	svc := oidcauth.NewAuth(e.cfg, flowConfig)
	tokenData, err := svc.RefreshTokens(ctx, refreshToken)
	if err != nil {
		return nil, err
	}
	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}
	auth.Metadata["type"] = "oidc"
	auth.Metadata["access_token"] = tokenData.AccessToken
	auth.Metadata["refresh_token"] = firstNonEmpty(tokenData.RefreshToken, refreshToken)
	auth.Metadata["id_token"] = tokenData.IDToken
	auth.Metadata["token_type"] = tokenData.TokenType
	auth.Metadata["scope"] = tokenData.Scope
	auth.Metadata["expired"] = tokenData.Expire
	auth.Metadata["email"] = tokenData.Email
	auth.Metadata["subject"] = tokenData.Subject
	auth.Metadata["username"] = tokenData.Username
	auth.Metadata["name"] = tokenData.Name
	auth.Metadata["issuer"] = tokenData.Issuer
	auth.Metadata["last_refresh"] = time.Now().UTC().Format(time.RFC3339)
	if len(flowConfig.Headers) > 0 {
		auth.Metadata[oidcauth.MetadataHeadersKey] = oidcauth.CloneHeaders(flowConfig.Headers)
	} else {
		delete(auth.Metadata, oidcauth.MetadataHeadersKey)
	}
	if tokenData.Claims != nil {
		auth.Metadata["claims"] = tokenData.Claims
	}
	if auth.Attributes == nil {
		auth.Attributes = make(map[string]string)
	}
	auth.Attributes["issuer"] = tokenData.Issuer
	auth.Attributes["subject"] = tokenData.Subject
	auth.Attributes["client_id"] = flowConfig.ClientID
	auth.Attributes["oidc_name"] = flowConfig.Name
	auth.Attributes["chat_url"] = flowConfig.LLMChatURL
	auth.Attributes = oidcauth.SyncHeaderAttributes(auth.Attributes, flowConfig.Headers)
	return auth, nil
}

func (e *OIDCExecutor) executeEmbeddings(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	url := e.resolveEmbeddingURL(auth)
	if url == "" {
		return cliproxyexecutor.Response{}, statusErr{code: http.StatusUnauthorized, msg: "missing oidc embedding url"}
	}
	jwt := e.resolveBearerToken(auth)
	if jwt == "" {
		return cliproxyexecutor.Response{}, statusErr{code: http.StatusUnauthorized, msg: "missing oidc jwt"}
	}
	payload := req.Payload
	if len(payload) == 0 {
		payload = []byte("{}")
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return cliproxyexecutor.Response{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+jwt)
	httpReq.Header.Set("User-Agent", "cli-proxy-oidc")
	if auth != nil {
		util.ApplyCustomHeadersFromAttrs(httpReq, auth.Attributes)
	}

	e.recordRequest(ctx, auth, url, payload)
	httpClient := helps.NewProxyAwareHTTPClient(ctx, e.cfg, auth, 0)
	httpResp, err := httpClient.Do(httpReq)
	if err != nil {
		helps.RecordAPIResponseError(ctx, e.cfg, err)
		return cliproxyexecutor.Response{}, err
	}
	defer func() {
		if errClose := httpResp.Body.Close(); errClose != nil {
			log.Errorf("oidc executor: close response body error: %v", errClose)
		}
	}()
	helps.RecordAPIResponseMetadata(ctx, e.cfg, httpResp.StatusCode, httpResp.Header.Clone())
	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		helps.RecordAPIResponseError(ctx, e.cfg, err)
		return cliproxyexecutor.Response{}, err
	}
	helps.AppendAPIResponseChunk(ctx, e.cfg, body)
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		return cliproxyexecutor.Response{}, statusErr{code: httpResp.StatusCode, msg: string(body)}
	}
	return cliproxyexecutor.Response{Payload: body, Headers: httpResp.Header.Clone()}, nil
}

func (e *OIDCExecutor) recordRequest(ctx context.Context, auth *cliproxyauth.Auth, url string, body []byte) {
	var authID, authLabel, authType, authValue string
	if auth != nil {
		authID = auth.ID
		authLabel = auth.Label
		authType, authValue = auth.AccountInfo()
	}
	helps.RecordAPIRequest(ctx, e.cfg, helps.UpstreamRequestLog{
		URL:       url,
		Method:    http.MethodPost,
		Provider:  e.Identifier(),
		AuthID:    authID,
		AuthLabel: authLabel,
		AuthType:  authType,
		AuthValue: authValue,
		Body:      body,
	})
}

func (e *OIDCExecutor) resolveBearerToken(auth *cliproxyauth.Auth) string {
	if auth == nil {
		return ""
	}
	if token := metadataNestedStringValue(auth.Metadata, "id_token"); token != "" {
		return token
	}
	if token := metadataNestedStringValue(auth.Metadata, "access_token"); token != "" {
		return token
	}
	if auth.Attributes != nil {
		if token := strings.TrimSpace(auth.Attributes["id_token"]); token != "" {
			return token
		}
		if token := strings.TrimSpace(auth.Attributes["access_token"]); token != "" {
			return token
		}
	}
	return ""
}

func (e *OIDCExecutor) resolveChatURL(auth *cliproxyauth.Auth) string {
	if auth == nil {
		return ""
	}
	if auth.Attributes != nil {
		if url := strings.TrimSpace(auth.Attributes["chat_url"]); url != "" {
			return url
		}
	}
	if auth.Metadata != nil {
		if url, ok := auth.Metadata["llm_chat_url"].(string); ok {
			return strings.TrimSpace(url)
		}
	}
	return ""
}

func (e *OIDCExecutor) resolveEmbeddingURL(auth *cliproxyauth.Auth) string {
	if auth == nil {
		return ""
	}
	if auth.Attributes != nil {
		if url := strings.TrimSpace(auth.Attributes["embedding_url"]); url != "" {
			return url
		}
	}
	if auth.Metadata != nil {
		if url, ok := auth.Metadata["embedding_url"].(string); ok {
			return strings.TrimSpace(url)
		}
	}
	return ""
}

func isOIDCEmbeddingRequest(opts cliproxyexecutor.Options) bool {
	return strings.EqualFold(strings.TrimSpace(opts.Alt), "embeddings")
}

func oidcTargetFormat(chatURL string) sdktranslator.Format {
	if oidcUsesResponsesAPI(chatURL) {
		return sdktranslator.FormatOpenAIResponse
	}
	return sdktranslator.FormatOpenAI
}

func oidcUsesResponsesAPI(chatURL string) bool {
	trimmed := strings.TrimSpace(chatURL)
	if trimmed == "" {
		return false
	}
	parsed, err := url.Parse(trimmed)
	path := trimmed
	if err == nil && parsed != nil && strings.TrimSpace(parsed.Path) != "" {
		path = parsed.Path
	}
	path = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(path), "/"))
	return strings.HasSuffix(path, "/responses") || path == "responses"
}

func metadataStringMap(metadata map[string]any) map[string]string {
	if len(metadata) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(metadata))
	for key, value := range metadata {
		switch typed := value.(type) {
		case string:
			out[key] = typed
		case []byte:
			out[key] = string(typed)
		default:
			if encoded, err := json.Marshal(typed); err == nil {
				out[key] = string(encoded)
			}
		}
	}
	return out
}

func mirrorMetadataKey(metadata map[string]string, sourceKey, targetKey string) {
	if metadata == nil || targetKey == "" {
		return
	}
	if strings.TrimSpace(metadata[targetKey]) != "" {
		return
	}
	if source := strings.TrimSpace(metadata[sourceKey]); source != "" {
		metadata[targetKey] = source
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func metadataNestedStringValue(metadata map[string]any, key string) string {
	if len(metadata) == 0 || strings.TrimSpace(key) == "" {
		return ""
	}
	if value := metadataValueAsString(metadata[key]); value != "" {
		return value
	}
	for _, nestedKey := range []string{"token", "Token"} {
		switch nested := metadata[nestedKey].(type) {
		case map[string]any:
			if value := metadataValueAsString(nested[key]); value != "" {
				return value
			}
		case map[string]string:
			if value := strings.TrimSpace(nested[key]); value != "" {
				return value
			}
		}
	}
	return ""
}

func metadataValueAsString(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case []byte:
		return strings.TrimSpace(string(typed))
	default:
		return ""
	}
}
