package agent

import (
	"encoding/json"
	"os"
	"strings"
	"time"

	"boring-swarm/cli/bsw/logscan"
)

type ActivityState string

const (
	StateUnknown      ActivityState = "unknown"
	StateActive       ActivityState = "active"
	StateWaitingInput ActivityState = "waiting_input"
	StateIdle         ActivityState = "idle"
	StateBlocked      ActivityState = "blocked"
	StateExited       ActivityState = "exited"
)

type Detection struct {
	State        ActivityState
	SessionRef   string
	LastProgress time.Time
	Reason       string
}

func NormalizeProvider(p string) string {
	provider := strings.ToLower(strings.TrimSpace(p))
	switch provider {
	case "claude-code", "claude_code", "claude code", "claudecode", "ccc":
		return "claude"
	case "codex-cli", "codex_cli", "codex cli":
		return "codex"
	default:
		return provider
	}
}

func ResumeCommand(provider, sessionRef string) string {
	provider = NormalizeProvider(provider)
	sessionRef = strings.TrimSpace(sessionRef)
	if sessionRef == "" {
		return ""
	}
	bin := providerResumeBinary(provider)
	switch provider {
	case "codex":
		return bin + " resume " + sessionRef
	case "claude":
		return bin + " -r " + sessionRef
	default:
		return ""
	}
}

func providerResumeBinary(provider string) string {
	switch NormalizeProvider(provider) {
	case "codex":
		if v := strings.TrimSpace(os.Getenv("BSW_CODEX_BIN")); v != "" {
			return v
		}
		return "codex"
	case "claude":
		if v := strings.TrimSpace(os.Getenv("BSW_CLAUDE_BIN")); v != "" {
			return v
		}
		return "claude"
	default:
		return strings.TrimSpace(provider)
	}
}

func DetectFromLog(provider, path string, now time.Time) (Detection, error) {
	provider = NormalizeProvider(provider)
	d := Detection{State: StateUnknown}
	_, err := logscan.ForEachLine(path, logscan.DefaultMaxLineBytes, func(line string) bool {
		if line == "" {
			return true
		}
		lower := strings.ToLower(line)
		if strings.Contains(lower, "permission_request") || strings.Contains(lower, "waiting_input") {
			d.State = StateWaitingInput
			d.Reason = "provider_permission_request"
			d.LastProgress = now
		}

		var raw map[string]any
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			return true
		}
		t := asString(raw["type"])
		sub := asString(raw["subtype"])

		switch provider {
		case "codex":
			d = applyCodexEvent(d, raw, t, sub, now)
		case "claude":
			d = applyClaudeEvent(d, raw, t, sub, now)
		default:
			if t != "" {
				d.State = StateActive
				d.LastProgress = now
			}
		}
		return true
	})
	if err != nil {
		if os.IsNotExist(err) {
			return Detection{State: StateUnknown}, nil
		}
		return Detection{}, err
	}
	if d.LastProgress.IsZero() {
		if st, err := os.Stat(path); err == nil {
			d.LastProgress = st.ModTime()
		}
	}
	return d, nil
}

func applyCodexEvent(d Detection, raw map[string]any, t, _ string, now time.Time) Detection {
	t = strings.ToLower(strings.TrimSpace(t))
	if t == "thread.started" {
		if v := asString(raw["thread_id"]); v != "" {
			d.SessionRef = v
		}
		d.LastProgress = now
		d.State = StateActive
	}
	if strings.Contains(t, "approval") {
		d.State = StateWaitingInput
		d.Reason = "approval_required"
		d.LastProgress = now
	}
	if strings.Contains(t, "error") {
		d.State = StateBlocked
		d.Reason = "provider_error"
		d.LastProgress = now
	}
	if t == "turn.started" || strings.HasPrefix(t, "item.") {
		d.State = StateActive
		d.LastProgress = now
	}
	if t == "turn.completed" {
		d.State = StateIdle
		d.LastProgress = now
	}
	return d
}

func applyClaudeEvent(d Detection, raw map[string]any, t, sub string, now time.Time) Detection {
	t = strings.ToLower(strings.TrimSpace(t))
	sub = strings.ToLower(strings.TrimSpace(sub))
	if t == "system" && sub == "init" {
		if v := asString(raw["session_id"]); v != "" {
			d.SessionRef = v
		}
		d.State = StateActive
		d.LastProgress = now
	}
	if t == "system" && (sub == "permission_request" || sub == "permission-required") {
		d.State = StateWaitingInput
		d.Reason = "permission_request"
		d.LastProgress = now
	}
	if t == "assistant" || t == "tool_use" || t == "user" {
		if d.State != StateWaitingInput {
			d.State = StateActive
		}
		d.LastProgress = now
	}
	if t == "result" {
		if strings.HasPrefix(sub, "error") || asBool(raw["is_error"]) {
			d.State = StateBlocked
			d.Reason = "provider_error"
		} else if d.State != StateWaitingInput {
			d.State = StateIdle
		}
		d.LastProgress = now
	}
	return d
}

func asString(v any) string {
	s, _ := v.(string)
	return strings.TrimSpace(s)
}

func asBool(v any) bool {
	b, ok := v.(bool)
	return ok && b
}

