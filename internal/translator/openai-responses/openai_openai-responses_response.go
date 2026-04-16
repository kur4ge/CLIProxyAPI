package openai_responses

import (
	"bytes"
	"context"
	"time"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

var dataTag = []byte("data:")

type convertResponsesToOpenAIParams struct {
	ResponseID                string
	CreatedAt                 int64
	Model                     string
	FunctionCallIndex         int
	HasReceivedArgumentsDelta bool
	HasToolCallAnnounced      bool
}

// ConvertOpenAIResponsesResponseToOpenAI translates a single Responses SSE data chunk
// into an OpenAI Chat Completions streaming chunk.
func ConvertOpenAIResponsesResponseToOpenAI(_ context.Context, modelName string, originalRequestRawJSON, requestRawJSON, rawJSON []byte, param *any) [][]byte {
	_ = requestRawJSON
	if *param == nil {
		*param = &convertResponsesToOpenAIParams{
			Model:             modelName,
			FunctionCallIndex: -1,
		}
	}

	if !bytes.HasPrefix(rawJSON, dataTag) {
		return [][]byte{}
	}
	rawJSON = bytes.TrimSpace(rawJSON[len(dataTag):])
	if len(rawJSON) == 0 || bytes.Equal(rawJSON, []byte("[DONE]")) {
		return [][]byte{}
	}

	template := []byte(`{"id":"","object":"chat.completion.chunk","created":0,"model":"","choices":[{"index":0,"delta":{},"finish_reason":null,"native_finish_reason":null}]}`)
	root := gjson.ParseBytes(rawJSON)
	dataType := root.Get("type").String()
	st := (*param).(*convertResponsesToOpenAIParams)

	if dataType == "response.created" {
		st.ResponseID = root.Get("response.id").String()
		st.CreatedAt = root.Get("response.created_at").Int()
		st.Model = root.Get("response.model").String()
		return [][]byte{}
	}

	if v := root.Get("model"); v.Exists() {
		template, _ = sjson.SetBytes(template, "model", v.String())
	} else if st.Model != "" {
		template, _ = sjson.SetBytes(template, "model", st.Model)
	} else if modelName != "" {
		template, _ = sjson.SetBytes(template, "model", modelName)
	}
	template, _ = sjson.SetBytes(template, "created", st.CreatedAt)
	template, _ = sjson.SetBytes(template, "id", st.ResponseID)

	if usage := root.Get("response.usage"); usage.Exists() {
		template = applyUsageToChatCompletion(template, usage)
	}

	switch dataType {
	case "response.reasoning_summary_text.delta":
		if v := root.Get("delta"); v.Exists() {
			template, _ = sjson.SetBytes(template, "choices.0.delta.role", "assistant")
			template, _ = sjson.SetBytes(template, "choices.0.delta.reasoning_content", v.String())
		}
	case "response.reasoning_summary_text.done":
		template, _ = sjson.SetBytes(template, "choices.0.delta.role", "assistant")
		template, _ = sjson.SetBytes(template, "choices.0.delta.reasoning_content", "\n\n")
	case "response.output_text.delta":
		if v := root.Get("delta"); v.Exists() {
			template, _ = sjson.SetBytes(template, "choices.0.delta.role", "assistant")
			template, _ = sjson.SetBytes(template, "choices.0.delta.content", v.String())
		}
	case "response.completed":
		finishReason := "stop"
		if st.FunctionCallIndex != -1 {
			finishReason = "tool_calls"
		}
		template, _ = sjson.SetBytes(template, "choices.0.finish_reason", finishReason)
		template, _ = sjson.SetBytes(template, "choices.0.native_finish_reason", finishReason)
		if usage := root.Get("response.usage"); usage.Exists() {
			template = applyUsageToChatCompletion(template, usage)
		}
	case "response.output_item.added":
		item := root.Get("item")
		if item.Get("type").String() != "function_call" {
			return [][]byte{}
		}

		st.FunctionCallIndex++
		st.HasReceivedArgumentsDelta = false
		st.HasToolCallAnnounced = true

		functionCall := []byte(`{"index":0,"id":"","type":"function","function":{"name":"","arguments":""}}`)
		functionCall, _ = sjson.SetBytes(functionCall, "index", st.FunctionCallIndex)
		functionCall, _ = sjson.SetBytes(functionCall, "id", item.Get("call_id").String())

		name := restoreOriginalToolName(originalRequestRawJSON, item.Get("name").String())
		functionCall, _ = sjson.SetBytes(functionCall, "function.name", name)
		functionCall, _ = sjson.SetBytes(functionCall, "function.arguments", "")

		template, _ = sjson.SetBytes(template, "choices.0.delta.role", "assistant")
		template, _ = sjson.SetRawBytes(template, "choices.0.delta.tool_calls", []byte(`[]`))
		template, _ = sjson.SetRawBytes(template, "choices.0.delta.tool_calls.-1", functionCall)
	case "response.function_call_arguments.delta":
		st.HasReceivedArgumentsDelta = true

		functionCall := []byte(`{"index":0,"function":{"arguments":""}}`)
		functionCall, _ = sjson.SetBytes(functionCall, "index", st.FunctionCallIndex)
		functionCall, _ = sjson.SetBytes(functionCall, "function.arguments", root.Get("delta").String())

		template, _ = sjson.SetRawBytes(template, "choices.0.delta.tool_calls", []byte(`[]`))
		template, _ = sjson.SetRawBytes(template, "choices.0.delta.tool_calls.-1", functionCall)
	case "response.function_call_arguments.done":
		if st.HasReceivedArgumentsDelta {
			return [][]byte{}
		}

		functionCall := []byte(`{"index":0,"function":{"arguments":""}}`)
		functionCall, _ = sjson.SetBytes(functionCall, "index", st.FunctionCallIndex)
		functionCall, _ = sjson.SetBytes(functionCall, "function.arguments", root.Get("arguments").String())

		template, _ = sjson.SetRawBytes(template, "choices.0.delta.tool_calls", []byte(`[]`))
		template, _ = sjson.SetRawBytes(template, "choices.0.delta.tool_calls.-1", functionCall)
	case "response.output_item.done":
		item := root.Get("item")
		if item.Get("type").String() != "function_call" {
			return [][]byte{}
		}
		if st.HasToolCallAnnounced {
			st.HasToolCallAnnounced = false
			return [][]byte{}
		}

		st.FunctionCallIndex++
		functionCall := []byte(`{"index":0,"id":"","type":"function","function":{"name":"","arguments":""}}`)
		functionCall, _ = sjson.SetBytes(functionCall, "index", st.FunctionCallIndex)
		functionCall, _ = sjson.SetBytes(functionCall, "id", item.Get("call_id").String())
		functionCall, _ = sjson.SetBytes(functionCall, "function.name", restoreOriginalToolName(originalRequestRawJSON, item.Get("name").String()))
		functionCall, _ = sjson.SetBytes(functionCall, "function.arguments", item.Get("arguments").String())

		template, _ = sjson.SetBytes(template, "choices.0.delta.role", "assistant")
		template, _ = sjson.SetRawBytes(template, "choices.0.delta.tool_calls", []byte(`[]`))
		template, _ = sjson.SetRawBytes(template, "choices.0.delta.tool_calls.-1", functionCall)
	default:
		return [][]byte{}
	}

	return [][]byte{template}
}

// ConvertOpenAIResponsesResponseToOpenAINonStream converts an OpenAI Responses JSON response
// into an OpenAI Chat Completions JSON response.
func ConvertOpenAIResponsesResponseToOpenAINonStream(_ context.Context, _ string, originalRequestRawJSON, requestRawJSON, rawJSON []byte, _ *any) []byte {
	_ = requestRawJSON
	root := gjson.ParseBytes(rawJSON)

	response := root
	if root.Get("type").String() == "response.completed" && root.Get("response").Exists() {
		response = root.Get("response")
	}
	if response.Get("object").String() != "response" && !response.Get("output").Exists() {
		return []byte{}
	}

	template := []byte(`{"id":"","object":"chat.completion","created":0,"model":"","choices":[{"index":0,"message":{"role":"assistant","content":null,"reasoning_content":null,"tool_calls":null},"finish_reason":null,"native_finish_reason":null}]}`)

	if v := response.Get("model"); v.Exists() {
		template, _ = sjson.SetBytes(template, "model", v.String())
	}
	if v := response.Get("created_at"); v.Exists() {
		template, _ = sjson.SetBytes(template, "created", v.Int())
	} else {
		template, _ = sjson.SetBytes(template, "created", time.Now().Unix())
	}
	if v := response.Get("id"); v.Exists() {
		template, _ = sjson.SetBytes(template, "id", v.String())
	}
	if usage := response.Get("usage"); usage.Exists() {
		template = applyUsageToChatCompletion(template, usage)
	}

	var toolCalls [][]byte
	var contentText string
	var reasoningText string

	if output := response.Get("output"); output.IsArray() {
		for _, item := range output.Array() {
			switch item.Get("type").String() {
			case "reasoning":
				if summary := item.Get("summary"); summary.IsArray() {
					for _, part := range summary.Array() {
						if part.Get("type").String() == "summary_text" {
							reasoningText = part.Get("text").String()
							break
						}
					}
				}
			case "message":
				if content := item.Get("content"); content.IsArray() {
					for _, part := range content.Array() {
						if part.Get("type").String() == "output_text" {
							contentText = part.Get("text").String()
							break
						}
					}
				}
			case "function_call":
				functionCall := []byte(`{"id":"","type":"function","function":{"name":"","arguments":""}}`)
				functionCall, _ = sjson.SetBytes(functionCall, "id", item.Get("call_id").String())
				functionCall, _ = sjson.SetBytes(functionCall, "function.name", restoreOriginalToolName(originalRequestRawJSON, item.Get("name").String()))
				functionCall, _ = sjson.SetBytes(functionCall, "function.arguments", item.Get("arguments").String())
				toolCalls = append(toolCalls, functionCall)
			}
		}
	}

	if contentText != "" {
		template, _ = sjson.SetBytes(template, "choices.0.message.content", contentText)
		template, _ = sjson.SetBytes(template, "choices.0.message.role", "assistant")
	}
	if reasoningText != "" {
		template, _ = sjson.SetBytes(template, "choices.0.message.reasoning_content", reasoningText)
		template, _ = sjson.SetBytes(template, "choices.0.message.role", "assistant")
	}
	if len(toolCalls) > 0 {
		template, _ = sjson.SetRawBytes(template, "choices.0.message.tool_calls", []byte(`[]`))
		for _, toolCall := range toolCalls {
			template, _ = sjson.SetRawBytes(template, "choices.0.message.tool_calls.-1", toolCall)
		}
		template, _ = sjson.SetBytes(template, "choices.0.message.role", "assistant")
	}

	if status := response.Get("status").String(); status == "completed" || status == "" {
		finishReason := "stop"
		if len(toolCalls) > 0 {
			finishReason = "tool_calls"
		}
		template, _ = sjson.SetBytes(template, "choices.0.finish_reason", finishReason)
		template, _ = sjson.SetBytes(template, "choices.0.native_finish_reason", finishReason)
	}

	return template
}

func applyUsageToChatCompletion(template []byte, usage gjson.Result) []byte {
	if v := usage.Get("output_tokens"); v.Exists() {
		template, _ = sjson.SetBytes(template, "usage.completion_tokens", v.Int())
	}
	if v := usage.Get("total_tokens"); v.Exists() {
		template, _ = sjson.SetBytes(template, "usage.total_tokens", v.Int())
	}
	if v := usage.Get("input_tokens"); v.Exists() {
		template, _ = sjson.SetBytes(template, "usage.prompt_tokens", v.Int())
	}
	if v := usage.Get("input_tokens_details.cached_tokens"); v.Exists() {
		template, _ = sjson.SetBytes(template, "usage.prompt_tokens_details.cached_tokens", v.Int())
	}
	if v := usage.Get("output_tokens_details.reasoning_tokens"); v.Exists() {
		template, _ = sjson.SetBytes(template, "usage.completion_tokens_details.reasoning_tokens", v.Int())
	}
	return template
}

func restoreOriginalToolName(originalRequestRawJSON []byte, shortened string) string {
	if shortened == "" {
		return ""
	}
	rev := buildReverseMapFromOriginalOpenAI(originalRequestRawJSON)
	if original, ok := rev[shortened]; ok {
		return original
	}
	return shortened
}

func buildReverseMapFromOriginalOpenAI(original []byte) map[string]string {
	rev := map[string]string{}
	names := make([]string, 0)
	tools := gjson.GetBytes(original, "tools")
	if tools.IsArray() {
		for _, t := range tools.Array() {
			if t.Get("type").String() != "function" {
				continue
			}
			if v := t.Get("function.name"); v.Exists() {
				names = append(names, v.String())
			}
		}
	}
	if len(names) == 0 {
		return rev
	}
	for originalName, shortName := range buildShortNameMap(names) {
		rev[shortName] = originalName
	}
	return rev
}
