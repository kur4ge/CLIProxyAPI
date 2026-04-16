package openai_responses

import (
	"strconv"
	"strings"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// ConvertOpenAIRequestToOpenAIResponses converts an OpenAI Chat Completions request
// into an OpenAI Responses API request.
func ConvertOpenAIRequestToOpenAIResponses(modelName string, inputRawJSON []byte, stream bool) []byte {
	rawJSON := inputRawJSON
	root := gjson.ParseBytes(rawJSON)

	out := []byte(`{"model":"","input":[],"stream":false}`)
	out, _ = sjson.SetBytes(out, "model", modelName)
	out, _ = sjson.SetBytes(out, "stream", stream)

	if v := root.Get("temperature"); v.Exists() {
		out, _ = sjson.SetBytes(out, "temperature", v.Value())
	}
	if v := root.Get("top_p"); v.Exists() {
		out, _ = sjson.SetBytes(out, "top_p", v.Value())
	}
	if v := root.Get("top_logprobs"); v.Exists() {
		out, _ = sjson.SetBytes(out, "top_logprobs", v.Value())
	}
	if v := root.Get("parallel_tool_calls"); v.Exists() {
		out, _ = sjson.SetBytes(out, "parallel_tool_calls", v.Value())
	}
	if v := root.Get("service_tier"); v.Exists() {
		out, _ = sjson.SetBytes(out, "service_tier", v.Value())
	}
	if v := root.Get("user"); v.Exists() {
		out, _ = sjson.SetBytes(out, "user", v.Value())
	}
	if v := root.Get("metadata"); v.Exists() {
		out, _ = sjson.SetBytes(out, "metadata", v.Value())
	}
	if v := root.Get("truncation"); v.Exists() {
		out, _ = sjson.SetBytes(out, "truncation", v.Value())
	}
	if v := root.Get("prompt_cache_key"); v.Exists() {
		out, _ = sjson.SetBytes(out, "prompt_cache_key", v.Value())
	}
	if v := root.Get("previous_response_id"); v.Exists() {
		out, _ = sjson.SetBytes(out, "previous_response_id", v.Value())
	}
	if v := root.Get("store"); v.Exists() {
		out, _ = sjson.SetBytes(out, "store", v.Value())
	} else {
		out, _ = sjson.SetBytes(out, "store", false)
	}

	if v := root.Get("max_completion_tokens"); v.Exists() {
		out, _ = sjson.SetBytes(out, "max_output_tokens", v.Value())
	} else if v := root.Get("max_tokens"); v.Exists() {
		out, _ = sjson.SetBytes(out, "max_output_tokens", v.Value())
	}

	if v := root.Get("reasoning_effort"); v.Exists() {
		effort := strings.ToLower(strings.TrimSpace(v.String()))
		if effort != "" {
			out, _ = sjson.SetBytes(out, "reasoning.effort", effort)
		}
	}

	if rf := root.Get("response_format"); rf.Exists() {
		out = mapResponseFormatToResponses(out, rf, root.Get("text"))
	} else if text := root.Get("text"); text.Exists() {
		if v := text.Get("verbosity"); v.Exists() {
			out, _ = sjson.SetBytes(out, "text.verbosity", v.Value())
		}
	}

	originalToolNameMap := buildOriginalToolNameMap(root.Get("tools"))

	firstSystemConsumed := false
	if messages := root.Get("messages"); messages.Exists() && messages.IsArray() {
		for _, m := range messages.Array() {
			role := m.Get("role").String()
			if role == "system" && !firstSystemConsumed {
				if instructions := firstMessageText(m.Get("content")); instructions != "" {
					out, _ = sjson.SetBytes(out, "instructions", instructions)
					firstSystemConsumed = true
					continue
				}
			}

			switch role {
			case "tool":
				funcOutput := []byte(`{}`)
				funcOutput, _ = sjson.SetBytes(funcOutput, "type", "function_call_output")
				funcOutput, _ = sjson.SetBytes(funcOutput, "call_id", m.Get("tool_call_id").String())
				funcOutput, _ = sjson.SetBytes(funcOutput, "output", toolMessageContent(m.Get("content")))
				out, _ = sjson.SetRawBytes(out, "input.-1", funcOutput)
			default:
				msg := []byte(`{}`)
				msg, _ = sjson.SetBytes(msg, "type", "message")
				switch role {
				case "system":
					msg, _ = sjson.SetBytes(msg, "role", "developer")
				default:
					msg, _ = sjson.SetBytes(msg, "role", role)
				}
				msg, _ = sjson.SetRawBytes(msg, "content", []byte(`[]`))

				appendMessageContent(&msg, role, m.Get("content"))

				if role != "assistant" || len(gjson.GetBytes(msg, "content").Array()) > 0 {
					out, _ = sjson.SetRawBytes(out, "input.-1", msg)
				}

				if role == "assistant" {
					if toolCalls := m.Get("tool_calls"); toolCalls.Exists() && toolCalls.IsArray() {
						for _, tc := range toolCalls.Array() {
							if tc.Get("type").String() != "function" {
								continue
							}
							funcCall := []byte(`{}`)
							funcCall, _ = sjson.SetBytes(funcCall, "type", "function_call")
							funcCall, _ = sjson.SetBytes(funcCall, "call_id", tc.Get("id").String())
							name := tc.Get("function.name").String()
							if short, ok := originalToolNameMap[name]; ok {
								name = short
							} else {
								name = shortenNameIfNeeded(name)
							}
							funcCall, _ = sjson.SetBytes(funcCall, "name", name)
							funcCall, _ = sjson.SetBytes(funcCall, "arguments", tc.Get("function.arguments").String())
							out, _ = sjson.SetRawBytes(out, "input.-1", funcCall)
						}
					}
				}
			}
		}
	}

	if tools := root.Get("tools"); tools.Exists() && tools.IsArray() {
		out, _ = sjson.SetRawBytes(out, "tools", []byte(`[]`))
		for _, t := range tools.Array() {
			toolType := t.Get("type").String()
			if toolType != "" && toolType != "function" && t.IsObject() {
				out, _ = sjson.SetRawBytes(out, "tools.-1", []byte(t.Raw))
				continue
			}
			if toolType != "function" {
				continue
			}

			item := []byte(`{}`)
			item, _ = sjson.SetBytes(item, "type", "function")
			fn := t.Get("function")
			if v := fn.Get("name"); v.Exists() {
				name := v.String()
				if short, ok := originalToolNameMap[name]; ok {
					name = short
				} else {
					name = shortenNameIfNeeded(name)
				}
				item, _ = sjson.SetBytes(item, "name", name)
			}
			if v := fn.Get("description"); v.Exists() {
				item, _ = sjson.SetBytes(item, "description", v.Value())
			}
			if v := fn.Get("parameters"); v.Exists() {
				item, _ = sjson.SetRawBytes(item, "parameters", []byte(v.Raw))
			}
			if v := fn.Get("strict"); v.Exists() {
				item, _ = sjson.SetBytes(item, "strict", v.Value())
			}
			out, _ = sjson.SetRawBytes(out, "tools.-1", item)
		}
		if gjson.GetBytes(out, "tools.#").Int() == 0 {
			out, _ = sjson.DeleteBytes(out, "tools")
		}
	}

	if tc := root.Get("tool_choice"); tc.Exists() {
		switch {
		case tc.Type == gjson.String:
			out, _ = sjson.SetBytes(out, "tool_choice", tc.String())
		case tc.IsObject():
			tcType := tc.Get("type").String()
			if tcType == "function" {
				name := tc.Get("function.name").String()
				if name != "" {
					if short, ok := originalToolNameMap[name]; ok {
						name = short
					} else {
						name = shortenNameIfNeeded(name)
					}
				}
				choice := []byte(`{}`)
				choice, _ = sjson.SetBytes(choice, "type", "function")
				if name != "" {
					choice, _ = sjson.SetBytes(choice, "name", name)
				}
				out, _ = sjson.SetRawBytes(out, "tool_choice", choice)
			} else if tcType != "" {
				out, _ = sjson.SetRawBytes(out, "tool_choice", []byte(tc.Raw))
			}
		}
	}

	return out
}

func mapResponseFormatToResponses(out []byte, rf, text gjson.Result) []byte {
	if !gjson.GetBytes(out, "text").Exists() {
		out, _ = sjson.SetRawBytes(out, "text", []byte(`{}`))
	}

	switch rf.Get("type").String() {
	case "text":
		out, _ = sjson.SetBytes(out, "text.format.type", "text")
	case "json_schema":
		js := rf.Get("json_schema")
		if js.Exists() {
			out, _ = sjson.SetBytes(out, "text.format.type", "json_schema")
			if v := js.Get("name"); v.Exists() {
				out, _ = sjson.SetBytes(out, "text.format.name", v.Value())
			}
			if v := js.Get("strict"); v.Exists() {
				out, _ = sjson.SetBytes(out, "text.format.strict", v.Value())
			}
			if v := js.Get("schema"); v.Exists() {
				out, _ = sjson.SetRawBytes(out, "text.format.schema", []byte(v.Raw))
			}
		}
	}

	if v := text.Get("verbosity"); v.Exists() {
		out, _ = sjson.SetBytes(out, "text.verbosity", v.Value())
	}
	return out
}

func appendMessageContent(msg *[]byte, role string, content gjson.Result) {
	if !content.Exists() {
		return
	}
	if content.Type == gjson.String && content.String() != "" {
		partType := "input_text"
		if role == "assistant" {
			partType = "output_text"
		}
		part := []byte(`{}`)
		part, _ = sjson.SetBytes(part, "type", partType)
		part, _ = sjson.SetBytes(part, "text", content.String())
		*msg, _ = sjson.SetRawBytes(*msg, "content.-1", part)
		return
	}
	if !content.IsArray() {
		return
	}

	for _, it := range content.Array() {
		switch it.Get("type").String() {
		case "text":
			partType := "input_text"
			if role == "assistant" {
				partType = "output_text"
			}
			part := []byte(`{}`)
			part, _ = sjson.SetBytes(part, "type", partType)
			part, _ = sjson.SetBytes(part, "text", it.Get("text").String())
			*msg, _ = sjson.SetRawBytes(*msg, "content.-1", part)
		case "image_url":
			if role != "user" {
				continue
			}
			part := []byte(`{}`)
			part, _ = sjson.SetBytes(part, "type", "input_image")
			if u := it.Get("image_url.url"); u.Exists() {
				part, _ = sjson.SetBytes(part, "image_url", u.String())
			}
			*msg, _ = sjson.SetRawBytes(*msg, "content.-1", part)
		case "file":
			if role != "user" {
				continue
			}
			part := []byte(`{}`)
			part, _ = sjson.SetBytes(part, "type", "input_file")
			if v := it.Get("file.file_data"); v.Exists() {
				part, _ = sjson.SetBytes(part, "file_data", v.String())
			}
			if v := it.Get("file.filename"); v.Exists() {
				part, _ = sjson.SetBytes(part, "filename", v.String())
			}
			if v := it.Get("file.file_id"); v.Exists() {
				part, _ = sjson.SetBytes(part, "file_id", v.String())
			}
			*msg, _ = sjson.SetRawBytes(*msg, "content.-1", part)
		}
	}
}

func firstMessageText(content gjson.Result) string {
	if !content.Exists() {
		return ""
	}
	if content.Type == gjson.String {
		return content.String()
	}
	if content.IsArray() {
		var b strings.Builder
		for _, it := range content.Array() {
			if it.Get("type").String() == "text" {
				b.WriteString(it.Get("text").String())
			}
		}
		return b.String()
	}
	return ""
}

func toolMessageContent(content gjson.Result) string {
	if !content.Exists() {
		return ""
	}
	if content.Type == gjson.String {
		return content.String()
	}
	if content.IsArray() {
		var parts []string
		for _, it := range content.Array() {
			if it.Get("type").String() == "text" {
				parts = append(parts, it.Get("text").String())
			}
		}
		return strings.Join(parts, "")
	}
	return content.String()
}

func buildOriginalToolNameMap(tools gjson.Result) map[string]string {
	names := make([]string, 0)
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
		return map[string]string{}
	}
	return buildShortNameMap(names)
}

// shortenNameIfNeeded applies the simple shortening rule for a single name.
func shortenNameIfNeeded(name string) string {
	const limit = 64
	if len(name) <= limit {
		return name
	}
	if strings.HasPrefix(name, "mcp__") {
		idx := strings.LastIndex(name, "__")
		if idx > 0 {
			candidate := "mcp__" + name[idx+2:]
			if len(candidate) > limit {
				return candidate[:limit]
			}
			return candidate
		}
	}
	return name[:limit]
}

// buildShortNameMap generates unique short names (<=64) for the given list of names.
func buildShortNameMap(names []string) map[string]string {
	const limit = 64
	used := map[string]struct{}{}
	m := map[string]string{}

	baseCandidate := func(n string) string {
		if len(n) <= limit {
			return n
		}
		if strings.HasPrefix(n, "mcp__") {
			idx := strings.LastIndex(n, "__")
			if idx > 0 {
				cand := "mcp__" + n[idx+2:]
				if len(cand) > limit {
					cand = cand[:limit]
				}
				return cand
			}
		}
		return n[:limit]
	}

	makeUnique := func(cand string) string {
		if _, ok := used[cand]; !ok {
			return cand
		}
		base := cand
		for i := 1; ; i++ {
			suffix := "_" + strconv.Itoa(i)
			allowed := limit - len(suffix)
			if allowed < 0 {
				allowed = 0
			}
			tmp := base
			if len(tmp) > allowed {
				tmp = tmp[:allowed]
			}
			tmp = tmp + suffix
			if _, ok := used[tmp]; !ok {
				return tmp
			}
		}
	}

	for _, n := range names {
		cand := baseCandidate(n)
		uniq := makeUnique(cand)
		used[uniq] = struct{}{}
		m[n] = uniq
	}
	return m
}
