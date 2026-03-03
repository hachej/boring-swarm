package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNormalizeProviderAliases(t *testing.T) {
	if got := NormalizeProvider(" claude-code "); got != "claude" {
		t.Fatalf("NormalizeProvider(claude-code)=%q want claude", got)
	}
	if got := NormalizeProvider("ccc"); got != "claude" {
		t.Fatalf("NormalizeProvider(ccc)=%q want claude", got)
	}
	if got := NormalizeProvider("codex-cli"); got != "codex" {
		t.Fatalf("NormalizeProvider(codex-cli)=%q want codex", got)
	}
}

func TestResumeCommandClaudeCodeAlias(t *testing.T) {
	got := ResumeCommand("claude-code", "session-123")
	want := "claude -r session-123"
	if got != want {
		t.Fatalf("ResumeCommand=%q want %q", got, want)
	}
}

func TestResumeCommandUsesConfiguredBinary(t *testing.T) {
	t.Setenv("BSW_CLAUDE_BIN", "ccc")
	got := ResumeCommand("claude", "session-abc")
	want := "ccc -r session-abc"
	if got != want {
		t.Fatalf("ResumeCommand=%q want %q", got, want)
	}
}

func TestDetectFromLogHandlesLargeJSONLine(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "worker.log")
	huge := strings.Repeat("x", 3*1024*1024)
	line1 := `{"type":"item.completed","item":{"id":"1","type":"command_execution","aggregated_output":"` + huge + `"}}`
	line2 := `{"type":"thread.started","thread_id":"session-123"}`
	if err := os.WriteFile(logPath, []byte(line1+"\n"+line2+"\n"), 0o644); err != nil {
		t.Fatalf("write log: %v", err)
	}
	d, err := DetectFromLog("codex", logPath, time.Now().UTC())
	if err != nil {
		t.Fatalf("DetectFromLog error: %v", err)
	}
	if d.SessionRef != "session-123" {
		t.Fatalf("expected session ref session-123, got %q", d.SessionRef)
	}
}
