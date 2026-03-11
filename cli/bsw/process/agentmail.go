package process

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
)

// AgentMailConfig holds connection details for the Agent Mail server.
type AgentMailConfig struct {
	URL   string // e.g. http://127.0.0.1:8765/mcp/
	Token string // bearer token
}

// AgentMailRegistration is returned after registering a worker.
type AgentMailRegistration struct {
	Name string // the assigned agent name (e.g. "BlueLake")
}

// DefaultAgentMailConfig reads config from env vars, then Vault.
func DefaultAgentMailConfig() AgentMailConfig {
	url := envOrVault("AGENT_MAIL_URL", "secret/agent/mail", "url")
	if url == "" {
		url = "http://127.0.0.1:8765/mcp/"
	}
	token := envOrVault("AGENT_MAIL_TOKEN", "secret/agent/mail", "token")
	return AgentMailConfig{URL: url, Token: token}
}

// envOrVault reads from env var first, then falls back to Vault.
func envOrVault(envKey, vaultPath, vaultField string) string {
	if v := os.Getenv(envKey); v != "" {
		return v
	}
	return vaultGet(vaultPath, vaultField)
}

// vaultGet reads a single field from Vault. Returns "" on any error.
func vaultGet(path, field string) string {
	out, err := exec.Command("vault", "kv", "get", "-field="+field, path).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// RegisterWorker registers a worker agent in Agent Mail and returns the assigned name.
// It ensures the project exists, registers the agent, and sets contact policy to open.
func (c AgentMailConfig) RegisterWorker(projectKey, provider, model, taskDesc string) (*AgentMailRegistration, error) {
	if c.URL == "" || c.Token == "" {
		return nil, fmt.Errorf("agent mail not configured (set AGENT_MAIL_URL and AGENT_MAIL_TOKEN)")
	}

	// 1. Ensure project
	_, err := c.call("ensure_project", map[string]any{
		"human_key": projectKey,
	})
	if err != nil {
		return nil, fmt.Errorf("ensure_project: %w", err)
	}

	// 2. Register agent (auto-generated name)
	result, err := c.call("register_agent", map[string]any{
		"project_key":      projectKey,
		"program":          provider,
		"model":            model,
		"task_description": taskDesc,
	})
	if err != nil {
		return nil, fmt.Errorf("register_agent: %w", err)
	}

	// Extract name from structuredContent
	name := ""
	if sc, ok := result["structuredContent"].(map[string]any); ok {
		if n, ok := sc["name"].(string); ok {
			name = n
		}
	}
	if name == "" {
		return nil, fmt.Errorf("register_agent: no name in response")
	}

	// 3. Set contact policy to open so orchestrator can message the worker
	_, _ = c.call("set_contact_policy", map[string]any{
		"project_key": projectKey,
		"agent_name":  name,
		"policy":      "open",
	})

	return &AgentMailRegistration{Name: name}, nil
}

func (c AgentMailConfig) call(tool string, args map[string]any) (map[string]any, error) {
	payload := map[string]any{
		"jsonrpc": "2.0",
		"id":      "1",
		"method":  "tools/call",
		"params": map[string]any{
			"name":      tool,
			"arguments": args,
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", c.URL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var rpcResp map[string]any
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return nil, fmt.Errorf("invalid json: %s", string(respBody[:min(200, len(respBody))]))
	}

	if errObj, ok := rpcResp["error"]; ok {
		return nil, fmt.Errorf("rpc error: %v", errObj)
	}

	result, ok := rpcResp["result"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("unexpected result type")
	}

	// Check for tool-level error
	if isErr, ok := result["isError"].(bool); ok && isErr {
		if content, ok := result["content"].([]any); ok && len(content) > 0 {
			if block, ok := content[0].(map[string]any); ok {
				return nil, fmt.Errorf("%s", block["text"])
			}
		}
		return nil, fmt.Errorf("tool returned error")
	}

	return result, nil
}

// AgentMailEnv returns environment variables for the worker process.
func AgentMailEnv(projectKey, agentName string, cfg AgentMailConfig) []string {
	return []string{
		"AGENT_MAIL_PROJECT=" + projectKey,
		"AGENT_MAIL_AGENT=" + agentName,
		"AGENT_MAIL_URL=" + cfg.URL,
		"AGENT_MAIL_TOKEN=" + cfg.Token,
		"AGENT_MAIL_INTERVAL=120",
	}
}

// InboxCheckHookPath returns the path to the check_inbox.sh script.
func InboxCheckHookPath() string {
	candidates := []string{
		"/home/ubuntu/mcp_agent_mail/scripts/hooks/check_inbox.sh",
		"/home/ubuntu/mcp_agent_mail/.claude/hooks/check_inbox.sh",
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// FormatProviderEnv merges agent mail env vars with filtered base env.
func FormatProviderEnv(base []string, amEnv []string) []string {
	// Remove any existing AGENT_MAIL_ vars from base
	out := make([]string, 0, len(base)+len(amEnv))
	for _, e := range base {
		if !strings.HasPrefix(e, "AGENT_MAIL_") {
			out = append(out, e)
		}
	}
	return append(out, amEnv...)
}
