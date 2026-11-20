package executor

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/MoeForge/moego/base64"
	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	_ "github.com/router-for-me/CLIProxyAPI/v8/internal/translator"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

func TestOIDCResponsesIncompleteDoesNotCooldown(t *testing.T) {
	cases := []struct {
		name             string
		reason           string
		outputInTerminal bool
		wantStopReason   string
	}{
		{name: "length", reason: "length", outputInTerminal: true, wantStopReason: "max_tokens"},
		{name: "max output tokens", reason: "max_output_tokens", outputInTerminal: true, wantStopReason: "max_tokens"},
		{name: "length with collected output", reason: "length", wantStopReason: "max_tokens"},
		{name: "content filter", reason: "content_filter", outputInTerminal: true, wantStopReason: "refusal"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			const model = "deepseek-v4-1-flash-economy"
			const outputItem = `{"id":"rs_test","type":"reasoning","status":"incomplete","summary":[{"type":"summary_text","text":"The user said Hi."}],"encrypted_content":"test-signature"}`
			terminalDoc := ojson.NewDocString(`{"type":"response.incomplete","response":{"id":"resp_test","model":"deepseek-v4-1-flash-economy","status":"incomplete","incomplete_details":{},"output":[],"usage":{"input_tokens":44,"output_tokens":16,"output_tokens_details":{"reasoning_tokens":16},"total_tokens":60}}}`)
			_ = terminalDoc.Set("response.incomplete_details.reason", tc.reason)
			if tc.outputInTerminal {
				_ = terminalDoc.SetRawBytes("response.output", []byte("["+outputItem+"]"))
			}
			terminal := terminalDoc.String()
			var calls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				body, errRead := io.ReadAll(r.Body)
				if errRead != nil {
					t.Errorf("read upstream request: %v", errRead)
				}
				if got := ojson.GetBytes(body, "max_output_tokens").Int(); got != 1 {
					t.Errorf("max_output_tokens = %d, want 1; body=%s", got, body)
				}
				w.Header().Set("Content-Type", "text/event-stream")
				w.Header().Set("X-Request-Id", "oidc-incomplete-test")
				_, _ = io.WriteString(w, "data: "+`{"type":"response.created","response":{"id":"resp_test","status":"in_progress","output":[]}}`+"\n\n")
				_, _ = io.WriteString(w, "data: "+`{"type":"response.output_item.done","output_index":0,"item":`+outputItem+"}\n\n")
				_, _ = io.WriteString(w, "data: "+terminal+"\n\n")
			}))
			defer upstream.Close()

			cfg := &config.Config{
				OIDC: config.OIDCConfigs{{
					Name: "test", LLMEndpoint: upstream.URL + "/v1/responses",
					RequestFormat: "codex", ResponseFormat: "codex",
				}},
			}
			cfg.DisableImageGeneration = config.DisableImageGenerationPassthrough
			manager := coreauth.NewManager(nil, nil, nil)
			manager.SetConfig(cfg)
			manager.RegisterExecutor(NewOIDCExecutor(cfg))
			auth := &coreauth.Auth{
				ID: t.Name(), Provider: "oidc", Status: coreauth.StatusActive,
				Metadata: map[string]any{"oidc_name": "test", "access_token": "test-token"},
			}
			ctx := context.Background()
			if _, errRegister := manager.Register(ctx, auth); errRegister != nil {
				t.Fatalf("register auth: %v", errRegister)
			}
			reg := registry.GetGlobalRegistry()
			reg.RegisterClient(auth.ID, "oidc", []*registry.ModelInfo{{ID: model}})
			t.Cleanup(func() { reg.UnregisterClient(auth.ID) })
			payload := []byte(`{"model":"deepseek-v4-1-flash-economy","max_tokens":1,"messages":[{"role":"user","content":"Hi"}]}`)
			req := cliproxyexecutor.Request{Model: model, Payload: payload}
			opts := cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatClaude, OriginalRequest: payload}

			for attempt := 0; attempt < 2; attempt++ {
				resp, errExecute := manager.Execute(ctx, []string{"oidc"}, req, opts)
				if errExecute != nil {
					t.Fatalf("Execute attempt %d: %v", attempt+1, errExecute)
				}
				root := ojson.ParseBytes(resp.Payload)
				if got := root.Get("stop_reason").String(); got != tc.wantStopReason {
					t.Fatalf("stop_reason = %q, want %q; response=%s", got, tc.wantStopReason, resp.Payload)
				}
				if got := root.Get("content.0.thinking").String(); got != "The user said Hi." {
					t.Fatalf("thinking content = %q; response=%s", got, resp.Payload)
				}
				if got := root.Get("content.0.signature").String(); got != "test-signature" {
					t.Fatalf("thinking signature = %q; response=%s", got, resp.Payload)
				}
				if root.Get("usage.input_tokens").Int() != 44 || root.Get("usage.output_tokens").Int() != 16 {
					t.Fatalf("usage was not preserved: %s", resp.Payload)
				}
				if got := resp.Headers.Get("X-Request-Id"); got != "oidc-incomplete-test" {
					t.Fatalf("X-Request-Id = %q, want oidc-incomplete-test", got)
				}
				current, ok := manager.GetByID(auth.ID)
				if !ok || current.Unavailable || !current.NextRetryAfter.IsZero() {
					t.Fatalf("incomplete response changed credential availability: %#v", current)
				}
				if state := current.ModelStates[model]; state != nil && (state.Unavailable || !state.NextRetryAfter.IsZero()) {
					t.Fatalf("incomplete response cooled the model: %#v", state)
				}
				if reg.IsModelSuspendedForClient(auth.ID, model) {
					t.Fatal("incomplete response suspended the model")
				}
			}
			if got := calls.Load(); got != 2 {
				t.Fatalf("upstream requests = %d, want 2", got)
			}
		})
	}
}

func TestOIDCResponsesWithoutSuccessfulTerminalRemainErrors(t *testing.T) {
	cases := []struct {
		name       string
		event      string
		wantStatus int
	}{
		{
			name:       "missing terminal",
			event:      `{"type":"response.created","response":{"id":"resp_test","status":"in_progress","output":[]}}`,
			wantStatus: http.StatusRequestTimeout,
		},
		{
			name:       "context length exceeded",
			event:      `{"type":"response.failed","response":{"status":"failed","error":{"code":"context_length_exceeded","message":"maximum context length exceeded"}}}`,
			wantStatus: http.StatusBadRequest,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, "data: "+tc.event+"\n\n")
			}))
			defer upstream.Close()
			cfg := &config.Config{OIDC: config.OIDCConfigs{{
				Name: "test", LLMEndpoint: upstream.URL + "/v1/responses",
				RequestFormat: "codex", ResponseFormat: "codex",
			}}}
			auth := &coreauth.Auth{Provider: "oidc", Metadata: map[string]any{"oidc_name": "test"}}
			payload := []byte(`{"model":"gpt-5.4","max_tokens":1,"messages":[{"role":"user","content":"Hi"}]}`)
			_, errExecute := NewOIDCExecutor(cfg).Execute(context.Background(), auth,
				cliproxyexecutor.Request{Model: "gpt-5.4", Payload: payload},
				cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatClaude, OriginalRequest: payload})
			var status interface{ StatusCode() int }
			if !errors.As(errExecute, &status) || status.StatusCode() != tc.wantStatus {
				t.Fatalf("Execute error = %v, want HTTP %d", errExecute, tc.wantStatus)
			}
		})
	}
}

func TestOIDCPayloadRulesRemainFinal(t *testing.T) {
	cases := []struct {
		name   string
		format sdktranslator.Format
		stream bool
		retry  bool
	}{
		{name: "chat", format: sdktranslator.FormatOpenAI},
		{name: "chat stream", format: sdktranslator.FormatOpenAI, stream: true},
		{name: "responses", format: sdktranslator.FormatCodex},
		{name: "responses stream", format: sdktranslator.FormatCodex, stream: true},
		{name: "responses retry", format: sdktranslator.FormatCodex, retry: true},
		{name: "responses stream retry", format: sdktranslator.FormatCodex, stream: true, retry: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				attempt := calls.Add(1)
				body, errRead := io.ReadAll(r.Body)
				if errRead != nil {
					t.Errorf("read upstream request: %v", errRead)
				}
				root := ojson.ParseBytes(body)
				for field, want := range map[string]string{
					"model":                "configured-model",
					"instructions":         "user instructions",
					"previous_response_id": "user previous response",
				} {
					if got := root.Get(field).String(); got != want {
						t.Errorf("%s = %q, want %q; body=%s", field, got, want, body)
					}
				}
				if root.Get("stream_options").Exists() || root.Get("tools").Exists() {
					t.Errorf("filtered fields were restored: %s", body)
				}
				if tc.retry && attempt == 1 {
					w.WriteHeader(http.StatusBadRequest)
					_, _ = io.WriteString(w, `{"error":{"code":"invalid_encrypted_content","message":"invalid_encrypted_content"}}`)
					return
				}
				if tc.retry && root.Get("input.0.type").String() == "reasoning" {
					t.Errorf("retry did not remove rejected reasoning: %s", body)
				}
				if tc.format == sdktranslator.FormatCodex {
					w.Header().Set("Content-Type", "text/event-stream")
					_, _ = io.WriteString(w, "data: "+`{"type":"response.completed","response":{"id":"oidc-test","object":"response","status":"completed","output":[],"usage":{"input_tokens":3,"output_tokens":4,"total_tokens":7}}}`+"\n\n")
				} else if tc.stream {
					w.Header().Set("Content-Type", "text/event-stream")
					_, _ = io.WriteString(w, "data: "+`{"id":"oidc-test","choices":[{"index":0,"delta":{"content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":4,"total_tokens":7}}`+"\n\ndata: [DONE]\n\n")
				} else {
					w.Header().Set("Content-Type", "application/json")
					_, _ = io.WriteString(w, `{"id":"oidc-test","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":4,"total_tokens":7}}`)
				}
			}))
			defer upstream.Close()

			path := "/v1/chat/completions"
			if tc.format == sdktranslator.FormatCodex {
				path = "/v1/responses"
			}
			cfg := &config.Config{
				OIDC: config.OIDCConfigs{{
					Name: "test", LLMEndpoint: upstream.URL + path,
					RequestFormat: tc.format.String(), ResponseFormat: tc.format.String(),
				}},
				Payload: config.PayloadConfig{
					Override: []config.PayloadRule{{
						Models: []config.PayloadModelRule{{Name: "*"}},
						Params: map[string]any{
							"model": "configured-model", "instructions": "user instructions",
							"previous_response_id": "user previous response",
						},
					}},
					Filter: []config.PayloadFilterRule{{
						Models: []config.PayloadModelRule{{Name: "*"}},
						Params: []string{"stream_options", "tools"},
					}},
				},
			}
			doc := ojson.NewDocString(`{"model":"gpt-5.4","messages":[{"role":"user","content":"hello"}],"stream_options":{"include_usage":false}}`)
			if tc.format == sdktranslator.FormatCodex {
				rawSignature := make([]byte, 73)
				rawSignature[0] = 0x80
				_ = doc.Set("input", []map[string]any{
					{"type": "reasoning", "encrypted_content": base64.RawURLEncoding.EncodeToString(rawSignature)},
					{"type": "message", "role": "user", "content": "hello"},
				})
			}
			payload := doc.Bytes()
			req := cliproxyexecutor.Request{Model: "gpt-5.4", Payload: payload}
			opts := cliproxyexecutor.Options{SourceFormat: tc.format, OriginalRequest: payload, Stream: tc.stream}
			auth := &coreauth.Auth{ID: "oidc-payload-test", Provider: "oidc", Metadata: map[string]any{"oidc_name": "test"}}
			exec := NewOIDCExecutor(cfg)
			before := helps.PayloadConfigEvaluationCount()
			if tc.stream {
				result, errStream := exec.ExecuteStream(context.Background(), auth, req, opts)
				if errStream != nil {
					t.Fatalf("ExecuteStream: %v", errStream)
				}
				for chunk := range result.Chunks {
					if chunk.Err != nil {
						t.Fatalf("stream chunk: %v", chunk.Err)
					}
				}
			} else if _, errExecute := exec.Execute(context.Background(), auth, req, opts); errExecute != nil {
				t.Fatalf("Execute: %v", errExecute)
			}
			wantAttempts := int32(1)
			if tc.retry {
				wantAttempts = 2
			}
			if got := calls.Load(); got != wantAttempts {
				t.Fatalf("upstream requests = %d, want %d", got, wantAttempts)
			}
			if got := helps.PayloadConfigEvaluationCount() - before; got != int64(wantAttempts) {
				t.Fatalf("payload evaluations = %d, want one per request (%d)", got, wantAttempts)
			}
		})
	}
}

func TestOIDCCountTokensAppliesPayloadFilter(t *testing.T) {
	cfg := &config.Config{OIDC: config.OIDCConfigs{{Name: "test", RequestFormat: "openai", ResponseFormat: "openai"}}}
	auth := &coreauth.Auth{Provider: "oidc", Metadata: map[string]any{"oidc_name": "test"}}
	req := cliproxyexecutor.Request{
		Model:   "gpt-4",
		Payload: []byte(`{"model":"gpt-4","messages":[{"role":"user","content":"Count these words before applying a payload filter."}]}`),
	}
	opts := cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatOpenAI, OriginalRequest: req.Payload}
	before, errBefore := NewOIDCExecutor(cfg).CountTokens(context.Background(), auth, req, opts)
	if errBefore != nil {
		t.Fatalf("CountTokens before filter: %v", errBefore)
	}
	cfg.Payload.Filter = []config.PayloadFilterRule{{Models: []config.PayloadModelRule{{Name: "*"}}, Params: []string{"messages"}}}
	after, errAfter := NewOIDCExecutor(cfg).CountTokens(context.Background(), auth, req, opts)
	if errAfter != nil {
		t.Fatalf("CountTokens after filter: %v", errAfter)
	}
	beforeTokens := ojson.GetBytes(before.Payload, "usage.prompt_tokens").Int()
	afterTokens := ojson.GetBytes(after.Payload, "usage.prompt_tokens").Int()
	if afterTokens >= beforeTokens {
		t.Fatalf("filtered token count = %d, want less than original %d", afterTokens, beforeTokens)
	}
}
