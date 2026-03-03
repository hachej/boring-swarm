package process

import (
	"bytes"
	"strings"
	"testing"
)

func TestBuildProviderCommandCodexDefaultSandbox(t *testing.T) {
	t.Setenv("BSW_CODEX_SANDBOX", "")
	cmd, _, err := buildProviderCommand("codex", "gpt-5-codex", "", "system", "user", "/tmp/project")
	if err != nil {
		t.Fatalf("buildProviderCommand error: %v", err)
	}

	if !hasArgPair(cmd.Args, "--sandbox", "danger-full-access") {
		t.Fatalf("expected --sandbox danger-full-access, args=%v", cmd.Args)
	}
}

func TestBuildProviderCommandCodexEnvSandboxOverride(t *testing.T) {
	t.Setenv("BSW_CODEX_SANDBOX", "workspace-write")
	cmd, _, err := buildProviderCommand("codex", "gpt-5-codex", "", "system", "user", "/tmp/project")
	if err != nil {
		t.Fatalf("buildProviderCommand error: %v", err)
	}

	if !hasArgPair(cmd.Args, "--sandbox", "workspace-write") {
		t.Fatalf("expected --sandbox workspace-write, args=%v", cmd.Args)
	}
}

func TestBuildProviderCommandCodexWhitespaceSandboxFallsBack(t *testing.T) {
	t.Setenv("BSW_CODEX_SANDBOX", "   ")
	cmd, _, err := buildProviderCommand("codex", "gpt-5-codex", "", "system", "user", "/tmp/project")
	if err != nil {
		t.Fatalf("buildProviderCommand error: %v", err)
	}

	if !hasArgPair(cmd.Args, "--sandbox", "danger-full-access") {
		t.Fatalf("expected --sandbox danger-full-access fallback, args=%v", cmd.Args)
	}
}

func TestBuildProviderCommandClaudeCodeAlias(t *testing.T) {
	cmd, _, err := buildProviderCommand("claude-code", "claude-sonnet-4-5", "medium", "system", "user", "/tmp/project")
	if err != nil {
		t.Fatalf("buildProviderCommand error: %v", err)
	}
	if len(cmd.Args) == 0 || cmd.Args[0] != "claude" {
		t.Fatalf("expected claude binary for claude-code alias, args=%v", cmd.Args)
	}
	if !hasArgPair(cmd.Args, "--effort", "medium") {
		t.Fatalf("expected --effort medium for claude provider, args=%v", cmd.Args)
	}
}

func TestBuildProviderCommandCCCAlias(t *testing.T) {
	cmd, _, err := buildProviderCommand("ccc", "claude-sonnet-4-5", "", "system", "user", "/tmp/project")
	if err != nil {
		t.Fatalf("buildProviderCommand error: %v", err)
	}
	if len(cmd.Args) == 0 || cmd.Args[0] != "claude" {
		t.Fatalf("expected claude binary for ccc alias, args=%v", cmd.Args)
	}
}

func TestBuildUserPromptAddsProofDefaults(t *testing.T) {
	p := buildUserPrompt(RuntimeContextPayload{
		BeadID:          "bd-1",
		SourceLabel:     "needs-proof",
		AssignmentToken: "run-1:bd-1:1",
	})
	if !strings.Contains(p, "Proof queue defaults:") {
		t.Fatalf("expected proof defaults section in prompt")
	}
	if !strings.Contains(p, "Infra reliability checks:") {
		t.Fatalf("expected infra reliability checks section in prompt")
	}
}

func TestCappedLineWriterTruncatesLongLine(t *testing.T) {
	dst := &bytes.Buffer{}
	w := newCappedLineWriter(dst, 10)
	input := strings.Repeat("x", 32) + "\nshort\n"
	if _, err := w.Write([]byte(input)); err != nil {
		t.Fatalf("Write error: %v", err)
	}
	got := dst.String()
	if !strings.Contains(got, "xxxxxxxxxx") {
		t.Fatalf("expected preserved prefix in output, got=%q", got)
	}
	if !strings.Contains(got, "[bsw truncated 22 bytes from oversized log line]") {
		t.Fatalf("expected truncation marker in output, got=%q", got)
	}
	if !strings.Contains(got, "\nshort\n") {
		t.Fatalf("expected following lines to remain readable, got=%q", got)
	}
}

func hasArgPair(args []string, key, value string) bool {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == key && args[i+1] == value {
			return true
		}
	}
	return false
}
