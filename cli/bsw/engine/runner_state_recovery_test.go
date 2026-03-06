package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"boring-swarm/cli/bsw/process"
)

func TestExtractStateCandidatesFromLogLineAgentMessageJSON(t *testing.T) {
	line := `{"type":"item.completed","item":{"id":"x","type":"agent_message","text":"Impl done\nSTATE impl:done assignment=run-1:bd-1:2"}}`
	candidates := extractStateCandidatesFromLogLine(line)
	if len(candidates) != 1 {
		t.Fatalf("expected 1 candidate, got %d (%+v)", len(candidates), candidates)
	}
	if candidates[0].Event != "impl:done" {
		t.Fatalf("unexpected event: %q", candidates[0].Event)
	}
	if candidates[0].Token != "run-1:bd-1:2" {
		t.Fatalf("unexpected token: %q", candidates[0].Token)
	}
}

func TestRecoverStateFromRuntimeLogFiltersByTokenAndTransition(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "worker.log")
	content := "" +
		`{"type":"item.completed","item":{"id":"a","type":"agent_message","text":"STATE impl:done assignment=other:token"}}` + "\n" +
		`{"type":"item.completed","item":{"id":"b","type":"agent_message","text":"STATE impl:skipped assignment=run-x:bd-1:3"}}` + "\n" +
		`{"type":"item.completed","item":{"id":"c","type":"agent_message","text":"STATE impl:failed assignment=run-x:bd-1:3"}}` + "\n"
	if err := os.WriteFile(logPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write log: %v", err)
	}

	rt := process.WorkerRuntime{
		ProcessLogPath:  logPath,
		AssignmentToken: "run-x:bd-1:3",
	}
	transitions := map[string]string{
		"impl:done":   "closed",
		"impl:failed": "needs-impl",
	}

	got, ok, err := recoverStateFromRuntimeLog(rt, transitions)
	if err != nil {
		t.Fatalf("recoverStateFromRuntimeLog error: %v", err)
	}
	if !ok {
		t.Fatalf("expected recovered state")
	}
	if got.Event != "impl:failed" {
		t.Fatalf("unexpected recovered event %q", got.Event)
	}
	if got.Token != "run-x:bd-1:3" {
		t.Fatalf("unexpected recovered token %q", got.Token)
	}
}

func TestRecoverStateFromRuntimeLogWithLargeLine(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "worker.log")
	huge := strings.Repeat("y", 3*1024*1024)
	content := "" +
		`{"type":"item.completed","item":{"id":"z","type":"command_execution","aggregated_output":"` + huge + `"}}` + "\n" +
		`{"type":"item.completed","item":{"id":"c","type":"agent_message","text":"STATE impl:done assignment=run-a:bd-9:1"}}` + "\n"
	if err := os.WriteFile(logPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write log: %v", err)
	}

	rt := process.WorkerRuntime{
		ProcessLogPath:  logPath,
		AssignmentToken: "run-a:bd-9:1",
	}
	transitions := map[string]string{
		"impl:done": "closed",
	}

	got, ok, err := recoverStateFromRuntimeLog(rt, transitions)
	if err != nil {
		t.Fatalf("recoverStateFromRuntimeLog error: %v", err)
	}
	if !ok {
		t.Fatalf("expected recovered state")
	}
	if got.Event != "impl:done" {
		t.Fatalf("unexpected recovered event %q", got.Event)
	}
}
