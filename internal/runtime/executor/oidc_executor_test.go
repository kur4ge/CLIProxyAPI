package executor

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v6/sdk/translator"
)

func TestOIDCExecutorExecuteEmbeddingsUsesConfiguredURLAndJWT(t *testing.T) {
	var gotPath string
	var gotAuth string
	var gotBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"object":"list","data":[{"embedding":[0.1,0.2],"index":0}],"model":"text-embedding-3-large","usage":{"prompt_tokens":3,"total_tokens":3}}`))
	}))
	defer server.Close()

	exec := NewOIDCExecutor(nil)
	auth := &cliproxyauth.Auth{
		Provider: "oidc",
		Metadata: map[string]any{
			"id_token":      "jwt-token",
			"embedding_url": server.URL + "/custom/embeddings",
		},
	}

	resp, err := exec.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "text-embedding-3-large",
		Payload: []byte(`{"model":"text-embedding-3-large","input":"hello"}`),
	}, cliproxyexecutor.Options{
		Alt:          "embeddings",
		SourceFormat: sdktranslator.FromString("openai"),
	})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if gotPath != "/custom/embeddings" {
		t.Fatalf("path = %q", gotPath)
	}
	if gotAuth != "Bearer jwt-token" {
		t.Fatalf("Authorization = %q", gotAuth)
	}
	if !strings.Contains(gotBody, `"input":"hello"`) {
		t.Fatalf("body = %q", gotBody)
	}
	if !strings.Contains(string(resp.Payload), `"embedding"`) {
		t.Fatalf("response payload = %s", string(resp.Payload))
	}
}

func TestOIDCExecutorExecuteUsesResponsesPayloadWhenChatURLIsResponses(t *testing.T) {
	var gotPath string
	var gotAuth string
	var gotBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"resp_1","object":"response","created_at":0,"status":"completed","model":"gpt-5","output":[],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}`))
	}))
	defer server.Close()

	exec := NewOIDCExecutor(nil)
	auth := &cliproxyauth.Auth{
		Provider: "oidc",
		Metadata: map[string]any{
			"id_token":     "jwt-token",
			"llm_chat_url": server.URL + "/v1/responses",
		},
	}

	resp, err := exec.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "gpt-5",
		Payload: []byte(`{"model":"gpt-5","input":"hello"}`),
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FormatOpenAIResponse,
	})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if gotPath != "/v1/responses" {
		t.Fatalf("path = %q", gotPath)
	}
	if gotAuth != "Bearer jwt-token" {
		t.Fatalf("Authorization = %q", gotAuth)
	}
	if !strings.Contains(gotBody, `"input":"hello"`) {
		t.Fatalf("body = %q", gotBody)
	}
	if strings.Contains(gotBody, `"messages"`) {
		t.Fatalf("body unexpectedly contains messages: %q", gotBody)
	}
	if !strings.Contains(string(resp.Payload), `"object":"response"`) {
		t.Fatalf("response payload = %s", string(resp.Payload))
	}
}

func TestOIDCExecutorExecuteStreamUsesResponsesPayloadWhenChatURLIsResponses(t *testing.T) {
	var gotPath string
	var gotAuth string
	var gotBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",\"object\":\"response\",\"created_at\":0,\"status\":\"completed\",\"model\":\"gpt-5\",\"output\":[],\"usage\":{\"input_tokens\":1,\"output_tokens\":1,\"total_tokens\":2}}}\n\n"))
	}))
	defer server.Close()

	exec := NewOIDCExecutor(nil)
	auth := &cliproxyauth.Auth{
		Provider: "oidc",
		Metadata: map[string]any{
			"id_token":     "jwt-token",
			"llm_chat_url": server.URL + "/v1/responses",
		},
	}

	result, err := exec.ExecuteStream(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "gpt-5",
		Payload: []byte(`{"model":"gpt-5","input":"hello","stream":true}`),
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FormatOpenAIResponse,
		Stream:       true,
	})
	if err != nil {
		t.Fatalf("ExecuteStream() error = %v", err)
	}
	for chunk := range result.Chunks {
		if chunk.Err != nil {
			t.Fatalf("stream chunk error = %v", chunk.Err)
		}
	}
	if gotPath != "/v1/responses" {
		t.Fatalf("path = %q", gotPath)
	}
	if gotAuth != "Bearer jwt-token" {
		t.Fatalf("Authorization = %q", gotAuth)
	}
	if !strings.Contains(gotBody, `"input":"hello"`) {
		t.Fatalf("body = %q", gotBody)
	}
	if strings.Contains(gotBody, `"messages"`) {
		t.Fatalf("body unexpectedly contains messages: %q", gotBody)
	}
}

func TestOIDCExecutorRefreshUsesStoredOIDCMetadata(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oidc/v1/token" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm() error = %v", err)
		}
		if got := r.Form.Get("grant_type"); got != "refresh_token" {
			t.Fatalf("grant_type = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"access-2","token_type":"Bearer","expires_in":3600,"refresh_token":"refresh-2","id_token":"header.payload.sig","scope":"openid profile email"}`))
	}))
	defer server.Close()

	exec := NewOIDCExecutor(nil)
	auth := &cliproxyauth.Auth{
		Provider: "oidc",
		Metadata: map[string]any{
			"oidc_name":           "example",
			"oidc_domain":         server.URL,
			"oidc_token_path":     "/oidc/v1/token",
			"oidc_authorize_path": "/oidc/v1/authorize",
			"oidc_client_id":      "client-id",
			"refresh_token":       "refresh-1",
			"llm_chat_url":        server.URL + "/chat",
			"embedding_url":       server.URL + "/embeddings",
			"headers": map[string]string{
				"X-Test": "test-value",
			},
		},
		Attributes: map[string]string{
			"header:X-Old": "old-value",
		},
	}

	updated, err := exec.Refresh(context.Background(), auth)
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if got := updated.Metadata["access_token"]; got != "access-2" {
		t.Fatalf("access_token = %v", got)
	}
	if got := updated.Metadata["refresh_token"]; got != "refresh-2" {
		t.Fatalf("refresh_token = %v", got)
	}
	if got := updated.Attributes["chat_url"]; got != server.URL+"/chat" {
		t.Fatalf("chat_url = %q", got)
	}
	if got := updated.Attributes["header:X-Test"]; got != "test-value" {
		t.Fatalf("header:X-Test = %q", got)
	}
	if _, ok := updated.Attributes["header:X-Old"]; ok {
		t.Fatal("expected stale header:X-Old to be removed")
	}
}

func TestOIDCExecutorRefreshUsesLegacyNestedTokenRefreshToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm() error = %v", err)
		}
		if got := r.Form.Get("refresh_token"); got != "legacy-refresh-1" {
			t.Fatalf("refresh_token = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"access-2","token_type":"Bearer","expires_in":3600,"refresh_token":"refresh-2","id_token":"header.payload.sig"}`))
	}))
	defer server.Close()

	exec := NewOIDCExecutor(nil)
	auth := &cliproxyauth.Auth{
		Provider: "oidc",
		Metadata: map[string]any{
			"oidc_name":           "example",
			"oidc_domain":         server.URL,
			"oidc_token_path":     "/oidc/v1/token",
			"oidc_authorize_path": "/oidc/v1/authorize",
			"oidc_client_id":      "client-id",
			"token": map[string]any{
				"refresh_token": "legacy-refresh-1",
				"access_token":  "legacy-access-1",
				"id_token":      "legacy-id-1",
			},
			"llm_chat_url": server.URL + "/chat",
		},
	}

	updated, err := exec.Refresh(context.Background(), auth)
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if got := updated.Metadata["refresh_token"]; got != "refresh-2" {
		t.Fatalf("refresh_token = %v", got)
	}
	if got := updated.Metadata["access_token"]; got != "access-2" {
		t.Fatalf("access_token = %v", got)
	}
	if got := exec.resolveBearerToken(updated); got != "header.payload.sig" {
		t.Fatalf("resolveBearerToken() = %q", got)
	}
}
