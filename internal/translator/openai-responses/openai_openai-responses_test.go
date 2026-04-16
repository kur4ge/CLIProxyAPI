package openai_responses

import (
	"context"
	"testing"

	"github.com/tidwall/gjson"
)

func TestConvertOpenAIRequestToOpenAIResponses_ToolCallsAndOutputs(t *testing.T) {
	input := []byte(`{
		"model":"gpt-4o",
		"messages":[
			{"role":"system","content":"You are helpful."},
			{"role":"user","content":"Weather in Paris?"},
			{
				"role":"assistant",
				"content":"Let me check.",
				"tool_calls":[
					{
						"id":"call_1",
						"type":"function",
						"function":{
							"name":"get_weather",
							"arguments":"{\"city\":\"Paris\"}"
						}
					}
				]
			},
			{"role":"tool","tool_call_id":"call_1","content":"sunny, 22C"}
		],
		"tools":[
			{
				"type":"function",
				"function":{
					"name":"get_weather",
					"description":"Get weather",
					"parameters":{"type":"object","properties":{"city":{"type":"string"}}}
				}
			}
		],
		"tool_choice":{"type":"function","function":{"name":"get_weather"}}
	}`)

	out := ConvertOpenAIRequestToOpenAIResponses("gpt-4.1", input, true)
	result := gjson.ParseBytes(out)

	if got := result.Get("model").String(); got != "gpt-4.1" {
		t.Fatalf("model = %q, want %q", got, "gpt-4.1")
	}
	if !result.Get("stream").Bool() {
		t.Fatal("expected stream=true")
	}
	if got := result.Get("instructions").String(); got != "You are helpful." {
		t.Fatalf("instructions = %q, want %q", got, "You are helpful.")
	}

	items := result.Get("input").Array()
	if len(items) != 4 {
		t.Fatalf("expected 4 input items, got %d: %s", len(items), result.Get("input").Raw)
	}

	if got := items[0].Get("role").String(); got != "user" {
		t.Fatalf("input[0].role = %q, want user", got)
	}
	if got := items[1].Get("role").String(); got != "assistant" {
		t.Fatalf("input[1].role = %q, want assistant", got)
	}
	if got := items[1].Get("content.0.type").String(); got != "output_text" {
		t.Fatalf("assistant content type = %q, want output_text", got)
	}
	if got := items[2].Get("type").String(); got != "function_call" {
		t.Fatalf("input[2].type = %q, want function_call", got)
	}
	if got := items[2].Get("name").String(); got != "get_weather" {
		t.Fatalf("function_call name = %q, want get_weather", got)
	}
	if got := items[3].Get("type").String(); got != "function_call_output" {
		t.Fatalf("input[3].type = %q, want function_call_output", got)
	}
	if got := items[3].Get("output").String(); got != "sunny, 22C" {
		t.Fatalf("function_call_output output = %q, want %q", got, "sunny, 22C")
	}

	if got := result.Get("tools.0.name").String(); got != "get_weather" {
		t.Fatalf("tool name = %q, want get_weather", got)
	}
	if got := result.Get("tool_choice.type").String(); got != "function" {
		t.Fatalf("tool_choice.type = %q, want function", got)
	}
	if got := result.Get("tool_choice.name").String(); got != "get_weather" {
		t.Fatalf("tool_choice.name = %q, want get_weather", got)
	}
}

func TestConvertOpenAIRequestToOpenAIResponses_MapsParameters(t *testing.T) {
	input := []byte(`{
		"model":"gpt-4o",
		"messages":[{"role":"user","content":"hi"}],
		"max_completion_tokens":321,
		"reasoning_effort":"HIGH",
		"response_format":{
			"type":"json_schema",
			"json_schema":{
				"name":"answer",
				"strict":true,
				"schema":{"type":"object","properties":{"value":{"type":"string"}}}
			}
		},
		"text":{"verbosity":"low"},
		"temperature":0.2,
		"top_p":0.9,
		"metadata":{"source":"test"}
	}`)

	out := ConvertOpenAIRequestToOpenAIResponses("gpt-5", input, false)
	result := gjson.ParseBytes(out)

	if got := result.Get("max_output_tokens").Int(); got != 321 {
		t.Fatalf("max_output_tokens = %d, want 321", got)
	}
	if got := result.Get("reasoning.effort").String(); got != "high" {
		t.Fatalf("reasoning.effort = %q, want high", got)
	}
	if got := result.Get("text.format.type").String(); got != "json_schema" {
		t.Fatalf("text.format.type = %q, want json_schema", got)
	}
	if got := result.Get("text.format.name").String(); got != "answer" {
		t.Fatalf("text.format.name = %q, want answer", got)
	}
	if got := result.Get("text.verbosity").String(); got != "low" {
		t.Fatalf("text.verbosity = %q, want low", got)
	}
	if got := result.Get("temperature").Float(); got != 0.2 {
		t.Fatalf("temperature = %v, want 0.2", got)
	}
	if got := result.Get("top_p").Float(); got != 0.9 {
		t.Fatalf("top_p = %v, want 0.9", got)
	}
	if got := result.Get("metadata.source").String(); got != "test" {
		t.Fatalf("metadata.source = %q, want test", got)
	}
	if got := result.Get("store").Bool(); got {
		t.Fatal("expected default store=false")
	}
}

func TestConvertOpenAIResponsesResponseToOpenAINonStream(t *testing.T) {
	originalRequest := []byte(`{
		"tools":[
			{
				"type":"function",
				"function":{
					"name":"mcp__very_long_server_name_that_exceeds_the_sixty_four_character_limit__get_weather",
					"parameters":{"type":"object"}
				}
			}
		]
	}`)

	response := []byte(`{
		"id":"resp_123",
		"object":"response",
		"created_at":123456,
		"model":"gpt-5",
		"status":"completed",
		"output":[
			{"id":"rs_1","type":"reasoning","summary":[{"type":"summary_text","text":"thinking"}]},
			{"id":"msg_1","type":"message","status":"completed","role":"assistant","content":[{"type":"output_text","text":"hello"}]},
			{"id":"fc_1","type":"function_call","status":"completed","call_id":"call_1","name":"mcp__get_weather","arguments":"{\"city\":\"Paris\"}"}
		],
		"usage":{
			"input_tokens":10,
			"output_tokens":5,
			"total_tokens":15,
			"input_tokens_details":{"cached_tokens":2},
			"output_tokens_details":{"reasoning_tokens":1}
		}
	}`)

	out := ConvertOpenAIResponsesResponseToOpenAINonStream(context.Background(), "", originalRequest, nil, response, nil)
	result := gjson.ParseBytes(out)

	if got := result.Get("object").String(); got != "chat.completion" {
		t.Fatalf("object = %q, want chat.completion", got)
	}
	if got := result.Get("choices.0.message.content").String(); got != "hello" {
		t.Fatalf("content = %q, want hello", got)
	}
	if got := result.Get("choices.0.message.reasoning_content").String(); got != "thinking" {
		t.Fatalf("reasoning_content = %q, want thinking", got)
	}
	if got := result.Get("choices.0.message.tool_calls.0.function.name").String(); got != "mcp__very_long_server_name_that_exceeds_the_sixty_four_character_limit__get_weather" {
		t.Fatalf("tool name = %q, want original long name", got)
	}
	if got := result.Get("choices.0.finish_reason").String(); got != "tool_calls" {
		t.Fatalf("finish_reason = %q, want tool_calls", got)
	}
	if got := result.Get("usage.prompt_tokens").Int(); got != 10 {
		t.Fatalf("prompt_tokens = %d, want 10", got)
	}
	if got := result.Get("usage.completion_tokens").Int(); got != 5 {
		t.Fatalf("completion_tokens = %d, want 5", got)
	}
}
