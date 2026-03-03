package process

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"boring-swarm/v2/cli/bsw/agent"
)

type Manager struct {
	projectRoot string
}

type SpawnSpec struct {
	RunID              string
	Attempt            int
	BeadID             string
	BeadTitle          string
	BeadDescription    string
	SourceLabel        string
	AssignmentToken    string
	AllowedTransitions []string
	AgentName          string
	Provider           string
	Model              string
	Effort             string
	PromptPath         string
}

type RuntimeContextPayload struct {
	BeadID             string   `json:"bead_id"`
	BeadTitle          string   `json:"bead_title"`
	BeadDescription    string   `json:"bead_description"`
	SourceLabel        string   `json:"source_label"`
	AssignmentToken    string   `json:"assignment_token"`
	AllowedTransitions []string `json:"allowed_transitions"`
	RunID              string   `json:"run_id"`
	Attempt            int      `json:"attempt"`
}

func NewManager(projectRoot string) Manager {
	return Manager{projectRoot: projectRoot}
}

func (m Manager) Spawn(ctx context.Context, s SpawnSpec) (WorkerRuntime, error) {
	provider := agent.NormalizeProvider(s.Provider)
	systemPrompt, err := os.ReadFile(s.PromptPath)
	if err != nil {
		return WorkerRuntime{}, fmt.Errorf("read workers.prompt %s: %w", s.PromptPath, err)
	}

	payload := RuntimeContextPayload{
		BeadID:             s.BeadID,
		BeadTitle:          s.BeadTitle,
		BeadDescription:    s.BeadDescription,
		SourceLabel:        s.SourceLabel,
		AssignmentToken:    s.AssignmentToken,
		AllowedTransitions: append([]string(nil), s.AllowedTransitions...),
		RunID:              s.RunID,
		Attempt:            s.Attempt,
	}

	payloadPath := filepath.Join(m.projectRoot, ".bsw", "runtime", "runs", s.RunID, "payloads", fmt.Sprintf("%s-%d.json", s.BeadID, s.Attempt))
	if err := os.MkdirAll(filepath.Dir(payloadPath), 0o755); err != nil {
		return WorkerRuntime{}, err
	}
	pb, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return WorkerRuntime{}, err
	}
	if err := os.WriteFile(payloadPath, pb, 0o644); err != nil {
		return WorkerRuntime{}, err
	}

	logPath := filepath.Join(m.projectRoot, ".bsw", "runtime", "runs", s.RunID, "workers", fmt.Sprintf("%s-%d.log", s.BeadID, s.Attempt))
	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
		return WorkerRuntime{}, err
	}
	logf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return WorkerRuntime{}, err
	}
	logWriter := newCappedLineWriter(logf, workerLogMaxLineBytes())

	userPrompt := buildUserPrompt(payload)
	cmd, stdin, err := buildProviderCommand(provider, s.Model, s.Effort, string(systemPrompt), userPrompt, m.projectRoot)
	if err != nil {
		_ = logf.Close()
		return WorkerRuntime{}, err
	}
	cmd.Dir = m.projectRoot
	cmd.Env = filteredEnv("CLAUDECODE")
	cmd.Stdout = logWriter
	cmd.Stderr = logWriter

	if stdin != "" {
		pipe, err := cmd.StdinPipe()
		if err != nil {
			_ = logf.Close()
			return WorkerRuntime{}, err
		}
		go func() {
			defer pipe.Close()
			_, _ = pipe.Write([]byte(stdin))
		}()
	}

	if err := cmd.Start(); err != nil {
		_ = logf.Close()
		return WorkerRuntime{}, fmt.Errorf("spawn worker: %w", err)
	}
	go func() {
		_ = cmd.Wait()
		_ = logWriter.flushLine(false)
		_ = logf.Close()
	}()

	now := time.Now().UTC().Format(time.RFC3339)
	rt := WorkerRuntime{
		BeadID:             s.BeadID,
		Role:               "queue-worker",
		PID:                cmd.Process.Pid,
		Provider:           provider,
		AgentName:          s.AgentName,
		AssignmentToken:    s.AssignmentToken,
		SourceLabel:        s.SourceLabel,
		AllowedTransitions: append([]string(nil), s.AllowedTransitions...),
		RunID:              s.RunID,
		Attempt:            s.Attempt,
		StartedAt:          now,
		LastProgressTS:     now,
		ActivityState:      string(agent.StateActive),
		ProcessLogPath:     logPath,
		RuntimePayloadPath: payloadPath,
		PromptPath:         s.PromptPath,
	}
	return rt, nil
}

func buildProviderCommand(provider, model, effort, systemPrompt, userPrompt, projectRoot string) (*exec.Cmd, string, error) {
	provider = agent.NormalizeProvider(provider)
	switch provider {
	case "codex":
		bin := providerBinary("codex")
		sandboxMode := strings.TrimSpace(os.Getenv("BSW_CODEX_SANDBOX"))
		if sandboxMode == "" {
			sandboxMode = "danger-full-access"
		}
		args := []string{"exec", "--json", "--model", model, "--cd", projectRoot, "--sandbox", sandboxMode, "-"}
		cmd := exec.Command(bin, args...)
		stdin := systemPrompt + "\n\n" + userPrompt + "\n"
		return cmd, stdin, nil
	case "claude":
		bin := providerBinary("claude")
		args := []string{"-p", "--verbose", "--output-format", "stream-json", "--model", model}
		if strings.TrimSpace(effort) != "" {
			args = append(args, "--effort", strings.TrimSpace(effort))
		}
		args = append(args, "--system-prompt", systemPrompt, userPrompt)
		cmd := exec.Command(bin, args...)
		return cmd, "", nil
	default:
		return nil, "", fmt.Errorf("unsupported provider %q", provider)
	}
}

func providerBinary(provider string) string {
	provider = agent.NormalizeProvider(provider)
	switch provider {
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
		return provider
	}
}

func ResolveProviderBinary(provider string) string {
	return providerBinary(provider)
}

func buildUserPrompt(payload RuntimeContextPayload) string {
	b, _ := json.MarshalIndent(payload, "", "  ")
	body := strings.TrimSpace(`Runtime context (authoritative):
` + string(b) + `

Task contract:
1) Get bead details with: br show <bead-id>
2) Execute work according to system prompt.
3) Post exactly one terminal STATE line as a bead comment via br:
   br comments add <bead-id> "STATE <event> assignment=<token>"
   Use the exact assignment token from runtime context.
4) Valid events are only those listed in allowed_transitions.
5) Infra reliability checks:
   - Prefer bead-scoped checks; avoid broad/full-suite runs unless explicitly required by bead acceptance criteria.
   - If a command fails with infra symptoms (port in use, connection refused, no tests found from bad grep), retry once with corrected invocation before terminal STATE.
   - Keep commands reproducible from project root.
6) Bead state access must be via br CLI only (SQLite-native mode).
   - Do NOT read or edit .beads/issues.jsonl directly.
   - Do NOT write directly to .beads/beads.db.
7) Do not mutate labels or assignee.
8) Exit immediately after posting the terminal STATE comment.`)
	if isProofQueue(payload.SourceLabel) {
		body += "\n\nProof queue defaults:\n" +
			"- Run targeted bead checks first (single test/file/grep for the failing location).\n" +
			"- Escalate to full matrix/full-suite only if acceptance criteria explicitly require it, or targeted evidence is inconclusive.\n" +
			"- If targeted check clearly reproduces the failure, post terminal proof:failed without broad reruns."
	}
	return body
}

func isProofQueue(sourceLabel string) bool {
	label := strings.TrimSpace(strings.ToLower(sourceLabel))
	return label == "needs-proof" || label == "needs_proof" || label == "proof"
}

func workerLogMaxLineBytes() int {
	const def = 256 * 1024
	v := strings.TrimSpace(os.Getenv("BSW_WORKER_LOG_MAX_LINE_BYTES"))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 16*1024 {
		return def
	}
	return n
}

type cappedLineWriter struct {
	dst     io.Writer
	max     int
	mu      sync.Mutex
	lineBuf []byte
	dropped int
}

func newCappedLineWriter(dst io.Writer, maxLineBytes int) *cappedLineWriter {
	if maxLineBytes <= 0 {
		maxLineBytes = 256 * 1024
	}
	return &cappedLineWriter{
		dst:     dst,
		max:     maxLineBytes,
		lineBuf: make([]byte, 0, 4096),
	}
}

func (w *cappedLineWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, b := range p {
		if b == '\n' {
			if err := w.flushLineLocked(true); err != nil {
				return 0, err
			}
			continue
		}
		if len(w.lineBuf) < w.max {
			w.lineBuf = append(w.lineBuf, b)
		} else {
			w.dropped++
		}
	}
	return len(p), nil
}

func (w *cappedLineWriter) flushLine(withNewline bool) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.flushLineLocked(withNewline)
}

func (w *cappedLineWriter) flushLineLocked(withNewline bool) error {
	if len(w.lineBuf) > 0 {
		if _, err := w.dst.Write(w.lineBuf); err != nil {
			return err
		}
	}
	if w.dropped > 0 {
		msg := fmt.Sprintf(" ... [bsw truncated %d bytes from oversized log line]", w.dropped)
		if _, err := w.dst.Write([]byte(msg)); err != nil {
			return err
		}
	}
	if withNewline {
		if _, err := w.dst.Write([]byte{'\n'}); err != nil {
			return err
		}
	}
	w.lineBuf = w.lineBuf[:0]
	w.dropped = 0
	return nil
}

func (m Manager) Refresh(rt WorkerRuntime, now time.Time) (WorkerRuntime, error) {
	alive := IsAlive(rt.PID)
	d, err := agent.DetectFromLog(rt.Provider, rt.ProcessLogPath, now)
	if err != nil {
		return rt, err
	}
	if d.SessionRef != "" {
		rt.SessionRef = d.SessionRef
	}
	if rt.SessionRef != "" {
		rt.ResumeCommand = agent.ResumeCommand(rt.Provider, rt.SessionRef)
	}
	if !d.LastProgress.IsZero() {
		rt.LastProgressTS = d.LastProgress.UTC().Format(time.RFC3339)
	}
	rt.ActivityReason = strings.TrimSpace(d.Reason)
	if !alive {
		rt.ActivityState = string(agent.StateExited)
		if rt.ActivityReason == "" {
			rt.ActivityReason = "process_exited"
		}
	} else {
		if d.State == agent.StateUnknown {
			rt.ActivityState = string(agent.StateActive)
			if rt.ActivityReason == "" {
				rt.ActivityReason = "log_state_unknown"
			}
		} else {
			rt.ActivityState = string(d.State)
		}
	}
	return rt, nil
}

func IsAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = p.Signal(syscall.Signal(0))
	return err == nil
}

func Terminate(pid int) error {
	if pid <= 0 {
		return nil
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	if err := p.Signal(syscall.SIGTERM); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "process already finished") {
			return nil
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !IsAlive(pid) {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err := p.Signal(syscall.SIGKILL); err != nil {
		return err
	}
	return nil
}

func ParseTS(v string) time.Time {
	if strings.TrimSpace(v) == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(v))
	if err != nil {
		return time.Time{}
	}
	return t
}

func NextAttempt(existing []WorkerRuntime, beadID string) int {
	max := 0
	for _, rt := range existing {
		if strings.TrimSpace(rt.BeadID) != strings.TrimSpace(beadID) {
			continue
		}
		if rt.Attempt > max {
			max = rt.Attempt
		}
	}
	return max + 1
}

// filteredEnv returns os.Environ() with the named keys removed.
// This prevents parent-session env vars (e.g. CLAUDECODE) from leaking
// into spawned worker processes.
func filteredEnv(keys ...string) []string {
	drop := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		drop[strings.ToUpper(k)] = struct{}{}
	}
	env := os.Environ()
	out := make([]string, 0, len(env))
	for _, e := range env {
		if idx := strings.IndexByte(e, '='); idx > 0 {
			if _, ok := drop[strings.ToUpper(e[:idx])]; ok {
				continue
			}
		}
		out = append(out, e)
	}
	return out
}

func AgentName(runID, beadID string, attempt int) string {
	suffix := strings.ReplaceAll(strings.TrimSpace(beadID), "bd-", "")
	suffix = strings.ReplaceAll(suffix, ":", "")
	r := runID
	if len(r) > 8 {
		r = r[len(r)-8:]
	}
	return "worker-" + r + "-" + suffix + "-" + strconv.Itoa(attempt)
}
