package process

import (
	"os"
	"testing"
)

func TestNormalizeProvider(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"codex", "codex"},
		{"Codex", "codex"},
		{"CODEX", "codex"},
		{"openai", "codex"},
		{"OpenAI", "codex"},
		{"claude", "claude"},
		{"Claude", "claude"},
		{"CLAUDE", "claude"},
		{"anthropic", "claude"},
		{"Anthropic", "claude"},
		{"  claude  ", "claude"},
		{"unknown", "unknown"},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeProvider(tt.input)
			if got != tt.want {
				t.Errorf("normalizeProvider(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestShellQuote(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"simple", "hello", "'hello'"},
		{"spaces", "hello world", "'hello world'"},
		{"single quote", "it's", "'it'\\''s'"},
		{"empty", "", "''"},
		{"special chars", "foo;bar&&baz", "'foo;bar&&baz'"},
		{"dollar sign", "$HOME", "'$HOME'"},
		{"backticks", "`cmd`", "'`cmd`'"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shellQuote(tt.input)
			if got != tt.want {
				t.Errorf("shellQuote(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestProviderBinary(t *testing.T) {
	// Default binaries
	os.Unsetenv("BSW_CODEX_BIN")
	os.Unsetenv("BSW_CLAUDE_BIN")

	if got := providerBinary("codex"); got != "codex" {
		t.Errorf("providerBinary(codex) = %q, want %q", got, "codex")
	}
	if got := providerBinary("claude"); got != "claude" {
		t.Errorf("providerBinary(claude) = %q, want %q", got, "claude")
	}

	// Custom binaries
	t.Setenv("BSW_CODEX_BIN", "/usr/local/bin/codex-custom")
	if got := providerBinary("codex"); got != "/usr/local/bin/codex-custom" {
		t.Errorf("providerBinary(codex) with env = %q, want %q", got, "/usr/local/bin/codex-custom")
	}

	t.Setenv("BSW_CLAUDE_BIN", "/usr/local/bin/claude-custom")
	if got := providerBinary("claude"); got != "/usr/local/bin/claude-custom" {
		t.Errorf("providerBinary(claude) with env = %q, want %q", got, "/usr/local/bin/claude-custom")
	}
}

func TestFilteredEnv(t *testing.T) {
	// Set test env vars
	t.Setenv("BSW_TEST_KEEP", "keep-me")
	t.Setenv("CLAUDECODE", "should-drop")

	result := filteredEnv("CLAUDECODE")

	found := false
	dropped := false
	for _, e := range result {
		if e == "BSW_TEST_KEEP=keep-me" {
			found = true
		}
		if e == "CLAUDECODE=should-drop" {
			dropped = true
		}
	}

	if !found {
		t.Error("filteredEnv should keep BSW_TEST_KEEP")
	}
	if dropped {
		t.Error("filteredEnv should have dropped CLAUDECODE")
	}
}

func TestBuildProviderCommand(t *testing.T) {
	t.Setenv("BSW_CODEX_BIN", "codex")
	t.Setenv("BSW_CLAUDE_BIN", "claude")

	// Test codex command
	cmd, stdin, err := buildProviderCommand("codex", "gpt-4", "", "system prompt", "user prompt", "/project")
	if err != nil {
		t.Fatalf("buildProviderCommand(codex) error = %v", err)
	}
	if cmd == nil {
		t.Fatal("buildProviderCommand(codex) returned nil cmd")
	}
	if stdin == "" {
		t.Error("buildProviderCommand(codex) should return stdin content")
	}

	// Test claude command
	cmd, stdin, err = buildProviderCommand("claude", "opus", "high", "system prompt", "user prompt", "/project")
	if err != nil {
		t.Fatalf("buildProviderCommand(claude) error = %v", err)
	}
	if cmd == nil {
		t.Fatal("buildProviderCommand(claude) returned nil cmd")
	}
	if stdin != "" {
		t.Error("buildProviderCommand(claude) should not use stdin")
	}

	// Test unsupported provider
	_, _, err = buildProviderCommand("gemini", "", "", "sys", "usr", "/project")
	if err == nil {
		t.Error("buildProviderCommand(gemini) should return error")
	}
}

func TestBuildProviderTUICommand(t *testing.T) {
	t.Setenv("BSW_CODEX_BIN", "codex")
	t.Setenv("BSW_CLAUDE_BIN", "claude")

	// Test codex TUI command
	cmd, err := buildProviderTUICommand("codex", "gpt-4", "", "system prompt", "user prompt", "/project")
	if err != nil {
		t.Fatalf("buildProviderTUICommand(codex) error = %v", err)
	}
	if cmd == "" {
		t.Error("buildProviderTUICommand(codex) returned empty command")
	}

	// Test claude TUI command
	cmd, err = buildProviderTUICommand("claude", "opus", "high", "system prompt", "user prompt", "/project")
	if err != nil {
		t.Fatalf("buildProviderTUICommand(claude) error = %v", err)
	}
	if cmd == "" {
		t.Error("buildProviderTUICommand(claude) returned empty command")
	}

	// Test unsupported provider
	_, err = buildProviderTUICommand("gemini", "", "", "sys", "usr", "/project")
	if err == nil {
		t.Error("buildProviderTUICommand(gemini) should return error")
	}
}

func TestSpawnValidation(t *testing.T) {
	mgr := NewManager(t.TempDir())

	// Invalid worker ID
	_, err := mgr.Spawn(SpawnSpec{
		WorkerID: "../bad",
		Mode:     "bg",
		Provider: "codex",
	})
	if err == nil {
		t.Error("Spawn with invalid worker ID should fail")
	}

	// Invalid mode
	_, err = mgr.Spawn(SpawnSpec{
		WorkerID: "test-worker",
		Mode:     "invalid",
		Provider: "codex",
	})
	if err == nil {
		t.Error("Spawn with invalid mode should fail")
	}
}

func TestIsAlive(t *testing.T) {
	// Our own PID should be alive
	if !IsAlive(os.Getpid()) {
		t.Error("IsAlive(self) should be true")
	}

	// Non-existent PID
	if IsAlive(999999999) {
		t.Error("IsAlive(999999999) should be false")
	}

	// Zero PID
	if IsAlive(0) {
		t.Error("IsAlive(0) should be false")
	}

	// Negative PID
	if IsAlive(-1) {
		t.Error("IsAlive(-1) should be false")
	}
}

func TestProcStartTime(t *testing.T) {
	// Our own process should have a start time
	st := ProcStartTime(os.Getpid())
	if st == 0 {
		t.Error("ProcStartTime(self) should be non-zero on Linux")
	}

	// Non-existent PID
	st = ProcStartTime(999999999)
	if st != 0 {
		t.Errorf("ProcStartTime(nonexistent) = %d, want 0", st)
	}
}

func TestIsOurProcess(t *testing.T) {
	pid := os.Getpid()
	startTime := ProcStartTime(pid)

	// Same PID and start time — should be ours
	if !IsOurProcess(pid, startTime) {
		t.Error("IsOurProcess(self, correct start time) should be true")
	}

	// Same PID, zero start time — should fall back to PID check
	if !IsOurProcess(pid, 0) {
		t.Error("IsOurProcess(self, 0) should be true (fallback to PID check)")
	}

	// Same PID, wrong start time — recycled PID detection
	if IsOurProcess(pid, startTime+99999) {
		t.Error("IsOurProcess(self, wrong start time) should be false")
	}

	// Dead PID
	if IsOurProcess(999999999, 12345) {
		t.Error("IsOurProcess(nonexistent, any) should be false")
	}
}

func TestFormatProviderEnv(t *testing.T) {
	base := []string{"PATH=/usr/bin", "HOME=/home/user"}
	amEnv := []string{"AGENT_MAIL_URL=http://localhost:8765", "AGENT_MAIL_TOKEN=secret"}

	result := FormatProviderEnv(base, amEnv)

	// Should contain all base + agent mail env vars
	if len(result) < len(base)+len(amEnv) {
		t.Errorf("FormatProviderEnv returned %d items, want at least %d", len(result), len(base)+len(amEnv))
	}
}
