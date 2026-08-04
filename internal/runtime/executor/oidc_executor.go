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

	"github.com/router-for-me/CLIProxyAPI/v7/internal/auth/oidc"
	oidcauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/oidc"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/thinking"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/usage"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

type OIDCExecutor struct {
	oidcReasoningSanitize *OIDCReasoningEncryptedContentSanitize
	cfg                   *config.Config
}

func NewOIDCExecutor(cfg *config.Config) *OIDCExecutor {
	oidcReasoningSanitize := newOIDCReasoningEncryptedContentSanitize()
	return &OIDCExecutor{oidcReasoningSanitize: oidcReasoningSanitize, cfg: cfg}
}

func (e *OIDCExecutor) Identifier() string { return "oidc" }

func (e *OIDCExecutor) PrepareRequest(req *http.Request, auth *cliproxyauth.Auth) error {
	if req == nil {
		return nil
	}
	if token := e.resolveBearerToken(auth); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("User-Agent", "cli-proxy-oidc")

	headers := e.oidcHeaders(auth)
	seed := oidcSessionSeedFromContext(req.Context())

	for k, v := range headers {
		req.Header.Set(k, helps.RenderHeaderValue(v, seed))
	}

	if oidcFirstRequestFromContext(req.Context()) {
		for k, v := range e.oidcFirstRequestHeaders(auth) {
			if strings.TrimSpace(v) == "" {
				req.Header.Del(k)
				continue
			}
			req.Header.Set(k, helps.RenderHeaderValue(v, seed))
		}
	}
	return nil
}

type oidcSessionSeedContextKey struct{}

type oidcFirstRequestContextKey struct{}

// withOIDCSessionSeed stores the downstream session id used as a deterministic
// seed for ${random:...} header variables.
func withOIDCSessionSeed(ctx context.Context, seed string) context.Context {
	if ctx == nil || strings.TrimSpace(seed) == "" {
		return ctx
	}
	return context.WithValue(ctx, oidcSessionSeedContextKey{}, seed)
}

func oidcSessionSeedFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if seed, ok := ctx.Value(oidcSessionSeedContextKey{}).(string); ok {
		return seed
	}
	return ""
}

// withOIDCFirstRequest records whether the current execution is the first
// request of its session, so PrepareRequest (which may be retried) consistently
// applies first-request-headers.
func withOIDCFirstRequest(ctx context.Context, first bool) context.Context {
	if ctx == nil {
		return ctx
	}
	return context.WithValue(ctx, oidcFirstRequestContextKey{}, first)
}

func oidcFirstRequestFromContext(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	if first, ok := ctx.Value(oidcFirstRequestContextKey{}).(bool); ok {
		return first
	}
	return false
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
	if opts.Alt == "responses/compact" {
		return resp, statusErr{code: http.StatusNotImplemented, msg: "/responses/compact not supported"}
	}

	seedID := cliproxyauth.ExtractSessionID(opts.Headers, opts.OriginalRequest, opts.Metadata)
	ctx = withOIDCSessionSeed(ctx, seedID)
	ctx = withOIDCFirstRequest(ctx, helps.MarkSessionSeen(seedID))

	baseModel := thinking.ParseSuffix(req.Model).ModelName

	reporter := helps.NewUsageReporter(ctx, e.Identifier(), baseModel, auth)
	defer reporter.TrackFailure(ctx, &err)

	endpoint := e.resolveEndpoint(auth)
	if endpoint == "" {
		err = statusErr{code: http.StatusUnauthorized, msg: "missing oidc llm endpoint"}
		return
	}
	if oidcEndpointUsesResponsesAPI(endpoint) {
		return e.executeResponsesEndpoint(ctx, auth, req, opts, endpoint, baseModel, reporter)
	}

	from := opts.SourceFormat
	to := e.oidcRequestFormat(auth)
	originalPayloadSource := req.Payload
	if len(opts.OriginalRequest) > 0 {
		originalPayloadSource = opts.OriginalRequest
	}
	originalPayload := originalPayloadSource
	originalTranslated := sdktranslator.TranslateRequest(from, to, baseModel, originalPayload, opts.Stream)
	translated := sdktranslator.TranslateRequest(from, to, baseModel, req.Payload, opts.Stream)
	translated, err = thinking.ApplyThinking(translated, req.Model, from.String(), to.String(), e.Identifier())
	if err != nil {
		return resp, err
	}
	// Ensure the upstream model matches the resolved (alias-mapped) model name.
	translated, _ = sjson.SetBytes(translated, "model", baseModel)

	requestedModel := helps.PayloadRequestedModel(opts, req.Model)
	requestPath := helps.PayloadRequestPath(opts)
	translated = helps.ApplyPayloadConfigWithRoot(e.cfg, baseModel, to.String(), "", translated, originalTranslated, requestedModel, requestPath)
	if opts.Alt == "responses/compact" {
		if updated, errDelete := sjson.DeleteBytes(translated, "stream"); errDelete == nil {
			translated = updated
		}
	}

	e.recordRequest(ctx, auth, endpoint, translated)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(translated))
	if err != nil {
		return resp, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpResp, err := e.HttpRequest(ctx, auth, httpReq)
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
		helps.LogWithRequestID(ctx).Debugf("request error, error status: %d, error message: %s", httpResp.StatusCode, helps.SummarizeErrorBody(httpResp.Header.Get("Content-Type"), b))
		err = statusErr{code: httpResp.StatusCode, msg: string(b)}
		return resp, err
	}
	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		helps.RecordAPIResponseError(ctx, e.cfg, err)
		return resp, err
	}
	helps.AppendAPIResponseChunk(ctx, e.cfg, body)
	to = e.oidcResponseFormat(auth)
	usageDetail := parseOIDCUsage(to, body)
	reporter.Publish(ctx, usageDetail)
	helps.AddSessionTokens(oidcSessionSeedFromContext(ctx), usageDetail.InputTokens, usageDetail.OutputTokens)
	// Ensure we at least record the request even if upstream doesn't return usage
	reporter.EnsurePublished(ctx)
	// Translate response back to source format when needed

	var param any
	out := sdktranslator.TranslateNonStream(ctx, to, from, req.Model, opts.OriginalRequest, translated, body, &param)
	resp = cliproxyexecutor.Response{Payload: out, Headers: httpResp.Header.Clone()}
	return resp, nil
}

func (e *OIDCExecutor) executeResponsesEndpoint(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options, endpoint string, baseModel string, reporter *helps.UsageReporter) (resp cliproxyexecutor.Response, err error) {
	from := opts.SourceFormat
	to := e.oidcRequestFormat(auth)
	originalPayloadSource := req.Payload
	if len(opts.OriginalRequest) > 0 {
		originalPayloadSource = opts.OriginalRequest
	}
	originalPayload := originalPayloadSource
	originalTranslated, translated := translateCodexRequestPair(from, to, baseModel, originalPayload, req.Payload, false)

	translated, err = thinking.ApplyThinking(translated, req.Model, from.String(), to.String(), e.Identifier())
	if err != nil {
		return resp, err
	}

	requestedModel := helps.PayloadRequestedModel(opts, req.Model)
	requestPath := helps.PayloadRequestPath(opts)
	translated = helps.ApplyPayloadConfigWithRequest(e.cfg, baseModel, to.String(), from.String(), "", translated, originalTranslated, requestedModel, requestPath, opts.Headers)
	translated, _ = sjson.SetBytes(translated, "model", baseModel)
	translated, _ = sjson.SetBytes(translated, "stream", true)
	translated, _ = sjson.DeleteBytes(translated, "previous_response_id")
	translated, _ = sjson.DeleteBytes(translated, "prompt_cache_retention")
	translated, _ = sjson.DeleteBytes(translated, "safety_identifier")
	translated, _ = sjson.DeleteBytes(translated, "stream_options")
	translated = normalizeCodexInstructions(translated)
	if e.cfg == nil || e.cfg.DisableImageGeneration == config.DisableImageGenerationOff {
		translated = ensureImageGenerationTool(translated, baseModel, auth, opts.Headers)
	}
	translated = e.oidcReasoningSanitize.PreSanitize(ctx, e.Identifier(), translated)

	reporter.SetTranslatedReasoningEffort(translated, to.String())

	e.recordRequest(ctx, auth, endpoint, translated)

	httpClient := helps.NewProxyAwareHTTPClient(ctx, e.cfg, auth, 0)
	httpClient = reporter.TrackHTTPClient(httpClient)
	var httpResp *http.Response
	for attempt := 0; ; attempt++ {
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(translated))
		if err != nil {
			return resp, err
		}
		httpReq.Header.Set("Content-Type", "application/json")
		if err = e.PrepareRequest(httpReq, auth); err != nil {
			return resp, err
		}

		httpResp, err = httpClient.Do(httpReq)
		if err != nil {
			helps.RecordAPIResponseError(ctx, e.cfg, err)
			return resp, err
		}

		helps.RecordAPIResponseMetadata(ctx, e.cfg, httpResp.StatusCode, httpResp.Header.Clone())
		if httpResp.StatusCode >= 200 && httpResp.StatusCode < 300 {
			break
		}

		data, readErr := io.ReadAll(httpResp.Body)
		if errClose := httpResp.Body.Close(); errClose != nil {
			log.Errorf("oidc executor: close response body error: %v", errClose)
		}
		if readErr != nil {
			helps.RecordAPIResponseError(ctx, e.cfg, readErr)
			return resp, readErr
		}

		helps.AppendAPIResponseChunk(ctx, e.cfg, data)
		helps.LogWithRequestID(ctx).Debugf("request error, error status: %d, error message: %s", httpResp.StatusCode, helps.SummarizeErrorBody(httpResp.Header.Get("Content-Type"), data))
		err = newCodexStatusErr(httpResp.StatusCode, data)
		if attempt > 0 || !strings.Contains(err.Error(), "invalid_encrypted_content") {
			return resp, err
		}

		retriedPayload := e.oidcReasoningSanitize.Sanitize(ctx, e.Identifier(), translated)
		if bytes.Equal(retriedPayload, translated) {
			return resp, err
		}

		translated = retriedPayload
		helps.LogWithRequestID(ctx).Debugf("%s: retrying responses request after dropping invalid reasoning encrypted_content", e.Identifier())
	}
	defer func() {
		if errClose := httpResp.Body.Close(); errClose != nil {
			log.Errorf("oidc executor: close response body error: %v", errClose)
		}
	}()

	data, err := io.ReadAll(httpResp.Body)
	if err != nil {
		helps.RecordAPIResponseError(ctx, e.cfg, err)
		return resp, err
	}
	helps.AppendAPIResponseChunk(ctx, e.cfg, data)

	outputItemsByIndex := make(map[int64][]byte)
	var outputItemsFallback [][]byte
	for _, line := range bytes.Split(data, []byte("\n")) {
		if !bytes.HasPrefix(line, dataTag) {
			continue
		}

		eventData := bytes.TrimSpace(line[len(dataTag):])
		eventType := gjson.GetBytes(eventData, "type").String()

		if streamErr, ok := codexTerminalStreamContextLengthErr(eventData); ok {
			return resp, streamErr
		}

		switch eventType {
		case "response.output_item.done":
			collectCodexOutputItemDone(eventData, outputItemsByIndex, &outputItemsFallback)
		case "response.completed":
			if detail, ok := helps.ParseCodexUsage(eventData); ok {
				reporter.Publish(ctx, detail)
				helps.AddSessionTokens(oidcSessionSeedFromContext(ctx), detail.InputTokens, detail.OutputTokens)
			}
			publishCodexImageToolUsage(ctx, reporter, translated, eventData)
			reporter.EnsurePublished(ctx)

			completedData := patchCodexCompletedOutput(eventData, outputItemsByIndex, outputItemsFallback)
			var param any
			out := sdktranslator.TranslateNonStream(ctx, to, from, req.Model, originalPayload, translated, completedData, &param)
			resp = cliproxyexecutor.Response{Payload: out, Headers: httpResp.Header.Clone()}
			return resp, nil
		}
	}

	err = statusErr{code: http.StatusRequestTimeout, msg: "stream error: stream disconnected before completion: stream closed before response.completed"}
	return resp, err
}

func (e *OIDCExecutor) ExecuteStream(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (_ *cliproxyexecutor.StreamResult, err error) {
	if opts.Alt == "responses/compact" {
		return nil, statusErr{code: http.StatusNotImplemented, msg: "/responses/compact not supported"}
	}

	seedID := cliproxyauth.ExtractSessionID(opts.Headers, opts.OriginalRequest, opts.Metadata)
	ctx = withOIDCSessionSeed(ctx, seedID)
	ctx = withOIDCFirstRequest(ctx, helps.MarkSessionSeen(seedID))

	baseModel := thinking.ParseSuffix(req.Model).ModelName

	reporter := helps.NewUsageReporter(ctx, e.Identifier(), baseModel, auth)
	defer reporter.TrackFailure(ctx, &err)

	endpoint := e.resolveEndpoint(auth)
	if endpoint == "" {
		err = statusErr{code: http.StatusUnauthorized, msg: "missing oidc llm endpoint"}
		return nil, err
	}

	from := opts.SourceFormat
	to := e.oidcRequestFormat(auth)
	originalPayloadSource := req.Payload
	if len(opts.OriginalRequest) > 0 {
		originalPayloadSource = opts.OriginalRequest
	}
	originalPayload := originalPayloadSource
	originalTranslated := sdktranslator.TranslateRequest(from, to, baseModel, originalPayload, true)
	translated := sdktranslator.TranslateRequest(from, to, baseModel, req.Payload, true)

	translated, err = thinking.ApplyThinking(translated, req.Model, from.String(), to.String(), e.Identifier())
	if err != nil {
		return nil, err
	}
	// Ensure the upstream model matches the resolved (alias-mapped) model name.
	translated, _ = sjson.SetBytes(translated, "model", baseModel)

	requestedModel := helps.PayloadRequestedModel(opts, req.Model)
	requestPath := helps.PayloadRequestPath(opts)
	translated = helps.ApplyPayloadConfigWithRoot(e.cfg, baseModel, to.String(), "", translated, originalTranslated, requestedModel, requestPath)

	// Request usage data in the final streaming chunk so that token statistics
	// are captured even when the upstream is an OpenAI-compatible provider.
	translated, _ = sjson.SetBytes(translated, "stream_options.include_usage", true)

	// Sanitize the payload before sending it to the upstream
	translated = e.oidcReasoningSanitize.PreSanitize(ctx, e.Identifier(), translated)

	var httpResp *http.Response
	for attempt := 0; ; attempt++ {
		e.recordRequest(ctx, auth, endpoint, translated)

		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(translated))
		if err != nil {
			return nil, err
		}
		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("Accept", "text/event-stream")
		httpReq.Header.Set("Cache-Control", "no-cache")

		httpResp, err = e.HttpRequest(ctx, auth, httpReq)
		if err != nil {
			helps.RecordAPIResponseError(ctx, e.cfg, err)
			return nil, err
		}
		helps.RecordAPIResponseMetadata(ctx, e.cfg, httpResp.StatusCode, httpResp.Header.Clone())
		if httpResp.StatusCode >= 200 && httpResp.StatusCode < 300 {
			break
		}

		data, readErr := io.ReadAll(httpResp.Body)
		if errClose := httpResp.Body.Close(); errClose != nil {
			log.Errorf("oidc executor: close response body error: %v", errClose)
		}
		if readErr != nil {
			helps.RecordAPIResponseError(ctx, e.cfg, readErr)
			return nil, readErr
		}

		helps.AppendAPIResponseChunk(ctx, e.cfg, data)
		helps.LogWithRequestID(ctx).Debugf("request error, error status: %d, error message: %s", httpResp.StatusCode, helps.SummarizeErrorBody(httpResp.Header.Get("Content-Type"), data))
		if to == sdktranslator.FormatCodex {
			err = newCodexStatusErr(httpResp.StatusCode, data)
		} else {
			err = statusErr{code: httpResp.StatusCode, msg: string(data)}
		}

		if attempt > 0 || !strings.Contains(err.Error(), "invalid_encrypted_content") {
			return nil, err
		}

		retriedPayload := e.oidcReasoningSanitize.Sanitize(ctx, e.Identifier(), translated)
		if bytes.Equal(retriedPayload, translated) {
			return nil, err
		}

		translated = retriedPayload
		helps.LogWithRequestID(ctx).Debugf("%s: retrying stream request after dropping invalid reasoning encrypted_content", e.Identifier())
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
		var lastUsage usage.Detail
		var sawUsage bool
		to = e.oidcResponseFormat(auth)
		for scanner.Scan() {
			line := scanner.Bytes()
			helps.AppendAPIResponseChunk(ctx, e.cfg, line)
			if detail, ok := parseOIDCStreamUsage(to, line); ok {
				reporter.Publish(ctx, detail)
				lastUsage = detail
				sawUsage = true
			}
			trimmedLine := bytes.TrimSpace(line)
			if len(trimmedLine) == 0 {
				continue
			}

			if !bytes.HasPrefix(trimmedLine, []byte("data:")) {
				if bytes.HasPrefix(trimmedLine, []byte(":")) || bytes.HasPrefix(trimmedLine, []byte("event:")) ||
					bytes.HasPrefix(trimmedLine, []byte("id:")) || bytes.HasPrefix(trimmedLine, []byte("retry:")) {
					continue
				}
				if bytes.HasPrefix(trimmedLine, []byte("{")) || bytes.HasPrefix(trimmedLine, []byte("[")) {
					streamErr := statusErr{code: http.StatusBadGateway, msg: string(trimmedLine)}
					helps.RecordAPIResponseError(ctx, e.cfg, streamErr)
					reporter.PublishFailure(ctx, streamErr)
					select {
					case out <- cliproxyexecutor.StreamChunk{Err: streamErr}:
					case <-ctx.Done():
					}
					return
				}
				continue
			}

			// OpenAI-compatible streams must use SSE data lines.
			chunks := sdktranslator.TranslateStream(ctx, to, from, req.Model, opts.OriginalRequest, translated, bytes.Clone(trimmedLine), &param)
			for i := range chunks {
				select {
				case out <- cliproxyexecutor.StreamChunk{Payload: chunks[i]}:
				case <-ctx.Done():
					return
				}
			}
		}
		if errScan := scanner.Err(); errScan != nil {
			helps.RecordAPIResponseError(ctx, e.cfg, errScan)
			reporter.PublishFailure(ctx, errScan)
			select {
			case out <- cliproxyexecutor.StreamChunk{Err: errScan}:
			case <-ctx.Done():
			}
		} else {
			// In case the upstream close the stream without a terminal [DONE] marker.
			// Feed a synthetic done marker through the translator so pending
			// response.completed events are still emitted exactly once.
			chunks := sdktranslator.TranslateStream(ctx, to, from, req.Model, opts.OriginalRequest, translated, []byte("data: [DONE]"), &param)
			for i := range chunks {
				select {
				case out <- cliproxyexecutor.StreamChunk{Payload: chunks[i]}:
				case <-ctx.Done():
					return
				}
			}
		}
		// Ensure we record the request if no usage chunk was ever seen
		reporter.EnsurePublished(ctx)
		if sawUsage {
			helps.AddSessionTokens(oidcSessionSeedFromContext(ctx), lastUsage.InputTokens, lastUsage.OutputTokens)
		}
	}()
	return &cliproxyexecutor.StreamResult{Headers: httpResp.Header.Clone(), Chunks: out}, nil
}

func (e *OIDCExecutor) CountTokens(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	baseModel := thinking.ParseSuffix(req.Model).ModelName

	from := opts.SourceFormat
	to := e.oidcRequestFormat(auth)
	translated := sdktranslator.TranslateRequest(from, to, baseModel, req.Payload, false)

	modelForCounting := baseModel

	translated, err := thinking.ApplyThinking(translated, req.Model, from.String(), to.String(), e.Identifier())
	if err != nil {
		return cliproxyexecutor.Response{}, err
	}

	enc, err := helps.TokenizerForModel(modelForCounting)
	if err != nil {
		return cliproxyexecutor.Response{}, fmt.Errorf("openai compat executor: tokenizer init failed: %w", err)
	}

	count, err := helps.CountOpenAIChatTokens(enc, translated)
	if err != nil {
		return cliproxyexecutor.Response{}, fmt.Errorf("openai compat executor: token counting failed: %w", err)
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
	flowConfig, err := oidc.SelectOIDCConfig(e.cfg, metadataMap["oidc_name"])
	if err != nil {
		return nil, err
	}
	refreshToken := metadataNestedStringValue(auth.Metadata, "refresh_token")
	if refreshToken == "" {
		return auth, nil
	}
	svc := oidcauth.NewAuth(e.cfg, *flowConfig)
	tokenData, err := svc.RefreshTokens(ctx, refreshToken)
	if err != nil {
		return nil, err
	}
	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}
	auth.Metadata["id_token"] = tokenData.IDToken
	auth.Metadata["refresh_token"] = tokenData.RefreshToken
	auth.Metadata["access_token"] = tokenData.AccessToken
	auth.Metadata["expired"] = tokenData.Expired
	now := time.Now().Format(time.RFC3339)
	auth.Metadata["last_refresh"] = now
	if expiry := strings.TrimSpace(tokenData.Expired); expiry != "" {
		if ts, errParse := time.Parse(time.RFC3339, expiry); errParse == nil {
			auth.NextRefreshAfter = ts.UTC()
		}
	}
	return auth, nil
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
	if id_token := metadataNestedStringValue(auth.Metadata, "id_token"); id_token != "" {
		return id_token
	}
	if token := metadataNestedStringValue(auth.Metadata, "access_token"); token != "" {
		return token
	}
	return ""
}

func (e *OIDCExecutor) resolveEndpoint(auth *cliproxyauth.Auth) string {
	if auth == nil {
		return ""
	}
	config, err := oidc.SelectOIDCConfig(e.cfg, metadataNestedStringValue(auth.Metadata, "oidc_name"))
	if err != nil {
		return ""
	}
	return config.LLMEndpoint
}

func (e *OIDCExecutor) oidcHeaders(auth *cliproxyauth.Auth) map[string]string {
	if auth == nil {
		return nil
	}
	config, err := oidc.SelectOIDCConfig(e.cfg, metadataNestedStringValue(auth.Metadata, "oidc_name"))
	if err != nil {
		return nil
	}
	return config.Headers
}

func (e *OIDCExecutor) oidcFirstRequestHeaders(auth *cliproxyauth.Auth) map[string]string {
	if auth == nil {
		return nil
	}
	config, err := oidc.SelectOIDCConfig(e.cfg, metadataNestedStringValue(auth.Metadata, "oidc_name"))
	if err != nil {
		return nil
	}
	return config.FirstRequestHeaders
}

func (e *OIDCExecutor) oidcRequestFormat(auth *cliproxyauth.Auth) sdktranslator.Format {
	if auth == nil {
		return ""
	}
	config, err := oidc.SelectOIDCConfig(e.cfg, metadataNestedStringValue(auth.Metadata, "oidc_name"))
	if err != nil {
		return ""
	}
	return sdktranslator.Format(config.ResponseFormat)
}

func (e *OIDCExecutor) oidcResponseFormat(auth *cliproxyauth.Auth) sdktranslator.Format {
	if auth == nil {
		return ""
	}
	config, err := oidc.SelectOIDCConfig(e.cfg, metadataNestedStringValue(auth.Metadata, "oidc_name"))
	if err != nil {
		return ""
	}
	return sdktranslator.Format(config.ResponseFormat)
}

// parseOIDCStreamUsage extracts usage from a single SSE line according to the
// configured upstream response format. Falls back to OpenAI-style parsing for
// unknown formats.
func parseOIDCStreamUsage(format sdktranslator.Format, line []byte) (usage.Detail, bool) {
	switch format {
	case sdktranslator.FormatCodex:
		return helps.ParseCodexStreamUsage(line)
	case sdktranslator.FormatClaude:
		return helps.ParseClaudeStreamUsage(line)
	case sdktranslator.FormatGemini:
		return helps.ParseGeminiStreamUsage(line)
	case sdktranslator.FormatAntigravity:
		return helps.ParseAntigravityStreamUsage(line)
	default:
		return helps.ParseOpenAIStreamUsage(line)
	}
}

// parseOIDCUsage extracts usage from a non-stream response body according to the
// configured upstream response format. Falls back to OpenAI-style parsing for
// unknown formats.
func parseOIDCUsage(format sdktranslator.Format, body []byte) usage.Detail {
	switch format {
	case sdktranslator.FormatCodex:
		if detail, ok := helps.ParseCodexUsage(body); ok {
			return detail
		}
		return usage.Detail{}
	case sdktranslator.FormatClaude:
		return helps.ParseClaudeUsage(body)
	case sdktranslator.FormatGemini:
		return helps.ParseGeminiUsage(body)
	case sdktranslator.FormatAntigravity:
		return helps.ParseAntigravityUsage(body)
	default:
		return helps.ParseOpenAIUsage(body)
	}
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

func oidcEndpointUsesResponsesAPI(endpoint string) bool {
	trimmed := strings.TrimSpace(endpoint)
	if trimmed == "" {
		return false
	}
	parsed, err := url.Parse(trimmed)
	if err == nil && parsed.Path != "" {
		return strings.HasSuffix(strings.TrimSuffix(parsed.Path, "/"), "/responses")
	}
	return strings.HasSuffix(strings.TrimSuffix(trimmed, "/"), "/responses")
}
