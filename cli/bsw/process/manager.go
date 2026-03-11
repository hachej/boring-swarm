package process

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type SpawnSpec struct {
	BeadID        string
	Persona       string
	Provider      string
	Model         string
	Effort        string
	SystemPrompt  string // full prompt text
	UserPrompt    string // bead context
	ProjectRoot   string
	Mode          string // "tmux" | "bg"
	TmuxSession   string // join this session as a window (empty = create new session)
	AgentMailEnv  []string // AGENT_MAIL_* env vars for inbox nudge
	AgentMailName string   // agent name for tmux pane/window title
}

type Manager struct {
	projectRoot string
}

func NewManager(projectRoot string) Manager {
	return Manager{projectRoot: projectRoot}
}

// Spawn starts a worker in either background or tmux mode.
func (m Manager) Spawn(s SpawnSpec) (WorkerEntry, error) {
	if err := ValidateBeadID(s.BeadID); err != nil {
		return WorkerEntry{}, err
	}
	if s.Mode != "bg" && s.Mode != "tmux" {
		return WorkerEntry{}, fmt.Errorf("invalid mode %q (must be bg or tmux)", s.Mode)
	}

	provider := normalizeProvider(s.Provider)

	logDir := filepath.Join(m.projectRoot, ".bsw", "logs")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return WorkerEntry{}, err
	}
	logPath := filepath.Join(logDir, s.BeadID+".log")

	switch s.Mode {
	case "tmux":
		return m.spawnTmux(s, provider, logPath)
	default:
		return m.spawnBg(s, provider, logPath)
	}
}

func (m Manager) spawnBg(s SpawnSpec, provider, logPath string) (WorkerEntry, error) {
	cmd, stdin, err := buildProviderCommand(provider, s.Model, s.Effort, s.SystemPrompt, s.UserPrompt, s.ProjectRoot)
	if err != nil {
		return WorkerEntry{}, err
	}
	cmd.Dir = s.ProjectRoot
	cmd.Env = FormatProviderEnv(filteredEnv("CLAUDECODE"), s.AgentMailEnv)

	logf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return WorkerEntry{}, err
	}
	cmd.Stdout = logf
	cmd.Stderr = logf

	if stdin != "" {
		pipe, err := cmd.StdinPipe()
		if err != nil {
			logf.Close()
			return WorkerEntry{}, err
		}
		go func() {
			defer pipe.Close()
			pipe.Write([]byte(stdin))
		}()
	}

	// Put worker in its own process group so we can kill the entire tree
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		logf.Close()
		return WorkerEntry{}, fmt.Errorf("spawn worker: %w", err)
	}
	go func() {
		cmd.Wait()
		logf.Close()
	}()

	pid := cmd.Process.Pid
	return WorkerEntry{
		BeadID:      s.BeadID,
		Persona:     s.Persona,
		Provider:    provider,
		Mode:        "bg",
		PID:         pid,
		StartedAt:   time.Now().UTC().Format(time.RFC3339),
		StartTimeNs: procStartTime(pid),
		Log:         logPath,
	}, nil
}


func (m Manager) spawnTmux(s SpawnSpec, provider, logPath string) (WorkerEntry, error) {
	// Use agent mail name for tmux label if available, otherwise bead ID
	label := s.BeadID
	if s.AgentMailName != "" {
		label = s.AgentMailName
	}
	windowName := "bsw-" + label

	// Build the provider command — TUI mode for interactive tmux
	shellCmd, err := buildProviderTUICommand(provider, s.Model, s.Effort, s.SystemPrompt, s.UserPrompt, s.ProjectRoot)
	if err != nil {
		return WorkerEntry{}, err
	}

	// Export Agent Mail env vars, then run the provider command
	envExports := ""
	for _, e := range s.AgentMailEnv {
		envExports += "export " + shellQuote(e) + "; "
	}
	// TUI runs interactively, tee output to log via script(1) to preserve terminal
	fullCmd := fmt.Sprintf("cd %s && %sscript -q -c %s %s", shellQuote(s.ProjectRoot), envExports, shellQuote(shellCmd), shellQuote(logPath))

	// Either split a pane in an existing session, or create a new session
	var paneTarget string
	if s.TmuxSession != "" {
		// New window in the target session (each agent gets its own window)
		tmuxCmd := exec.Command("tmux", "new-window", "-t", s.TmuxSession, "-n", label, fullCmd)
		if err := tmuxCmd.Run(); err != nil {
			return WorkerEntry{}, fmt.Errorf("tmux new-window in %s: %w", s.TmuxSession, err)
		}
		// Get the pane ID of the new window
		out, err := exec.Command("tmux", "display-message", "-t", s.TmuxSession+":"+label, "-p", "#{pane_id}").Output()
		if err == nil {
			paneTarget = strings.TrimSpace(string(out))
		} else {
			paneTarget = s.TmuxSession + ":" + label
		}
	} else {
		// New detached session
		tmuxCmd := exec.Command("tmux", "new-session", "-d", "-s", windowName, fullCmd)
		if err := tmuxCmd.Run(); err != nil {
			return WorkerEntry{}, fmt.Errorf("tmux new-session: %w", err)
		}
		paneTarget = windowName
	}

	// Get the PID of the process inside the pane
	out, err := exec.Command("tmux", "list-panes", "-t", paneTarget, "-F", "#{pane_pid}").Output()
	if err != nil {
		return WorkerEntry{}, fmt.Errorf("tmux get pane pid: %w", err)
	}
	pid := 0
	fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &pid)

	return WorkerEntry{
		BeadID:      s.BeadID,
		Persona:     s.Persona,
		Provider:    provider,
		Mode:        "tmux",
		PID:         pid,
		Pane:        paneTarget,
		StartedAt:   time.Now().UTC().Format(time.RFC3339),
		StartTimeNs: procStartTime(pid),
		Log:         logPath,
	}, nil
}

func buildProviderCommand(provider, model, effort, systemPrompt, userPrompt, projectRoot string) (*exec.Cmd, string, error) {
	switch provider {
	case "codex":
		bin := providerBinary("codex")
		args := []string{"exec", "--json", "--dangerously-bypass-approvals-and-sandbox"}
		if model != "" {
			args = append(args, "--model", model)
		}
		args = append(args, "--cd", projectRoot, "-")
		cmd := exec.Command(bin, args...)
		stdin := systemPrompt + "\n\n" + userPrompt + "\n"
		return cmd, stdin, nil
	case "claude":
		bin := providerBinary("claude")
		args := []string{"-p", "--verbose", "--output-format", "stream-json", "--dangerously-skip-permissions"}
		if model != "" {
			args = append(args, "--model", model)
		}
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

// buildProviderShellCommand returns a non-interactive shell command string (for bg mode).
func buildProviderShellCommand(provider, model, effort, systemPrompt, userPrompt, projectRoot string) (string, error) {
	switch provider {
	case "codex":
		bin := providerBinary("codex")
		prompt := systemPrompt + "\n\n" + userPrompt
		parts := []string{"echo", shellQuote(prompt), "|", shellQuote(bin), "exec", "--json", "--dangerously-bypass-approvals-and-sandbox"}
		if model != "" {
			parts = append(parts, "--model", shellQuote(model))
		}
		parts = append(parts, "--cd", shellQuote(projectRoot), "-")
		return strings.Join(parts, " "), nil
	case "claude":
		bin := providerBinary("claude")
		parts := []string{shellQuote(bin), "-p", "--verbose", "--output-format", "stream-json", "--dangerously-skip-permissions"}
		if model != "" {
			parts = append(parts, "--model", shellQuote(model))
		}
		if strings.TrimSpace(effort) != "" {
			parts = append(parts, "--effort", shellQuote(strings.TrimSpace(effort)))
		}
		parts = append(parts, "--system-prompt", shellQuote(systemPrompt), shellQuote(userPrompt))
		return strings.Join(parts, " "), nil
	default:
		return "", fmt.Errorf("unsupported provider %q", provider)
	}
}

// buildProviderTUICommand returns a TUI command string for tmux mode (interactive terminal).
func buildProviderTUICommand(provider, model, effort, systemPrompt, userPrompt, projectRoot string) (string, error) {
	switch provider {
	case "codex":
		bin := providerBinary("codex")
		parts := []string{shellQuote(bin), "--dangerously-bypass-approvals-and-sandbox"}
		if model != "" {
			parts = append(parts, "--model", shellQuote(model))
		}
		parts = append(parts, "--cd", shellQuote(projectRoot))
		parts = append(parts, shellQuote(systemPrompt+"\n\n"+userPrompt))
		return strings.Join(parts, " "), nil
	case "claude":
		bin := providerBinary("claude")
		parts := []string{shellQuote(bin), "--dangerously-skip-permissions"}
		if model != "" {
			parts = append(parts, "--model", shellQuote(model))
		}
		if strings.TrimSpace(effort) != "" {
			parts = append(parts, "--effort", shellQuote(strings.TrimSpace(effort)))
		}
		parts = append(parts, "--system-prompt", shellQuote(systemPrompt), shellQuote(userPrompt))
		return strings.Join(parts, " "), nil
	default:
		return "", fmt.Errorf("unsupported provider %q", provider)
	}
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

func providerBinary(provider string) string {
	provider = normalizeProvider(provider)
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

func normalizeProvider(p string) string {
	s := strings.ToLower(strings.TrimSpace(p))
	switch s {
	case "codex", "openai":
		return "codex"
	case "claude", "anthropic":
		return "claude"
	default:
		return s
	}
}

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

func IsAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return p.Signal(syscall.Signal(0)) == nil
}

func Terminate(pid int) error {
	if pid <= 0 {
		return nil
	}

	// Try to kill the entire process group first (negative PID).
	// This catches subprocesses spawned by the worker.
	_ = syscall.Kill(-pid, syscall.SIGTERM)

	// Also signal the process directly in case Setpgid wasn't used.
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

	// Escalate to SIGKILL on both group and process
	_ = syscall.Kill(-pid, syscall.SIGKILL)
	return p.Signal(syscall.SIGKILL)
}

// TerminateTmux kills a tmux pane (not the whole session).
func TerminateTmux(pane string) error {
	if pane == "" {
		return nil
	}
	// Try kill-pane first — this only removes the worker's pane, not the session.
	if err := exec.Command("tmux", "kill-pane", "-t", pane).Run(); err != nil {
		// Fall back to kill-window if pane target looks like a session/window name
		return exec.Command("tmux", "kill-window", "-t", pane).Run()
	}
	return nil
}

// procStartTime reads the process start time from /proc/<pid>/stat (field 22).
// Returns 0 if unreadable. Used to detect PID reuse.
func procStartTime(pid int) int64 {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	// Fields after the comm (which may contain spaces/parens) start after the last ')'.
	s := string(data)
	idx := strings.LastIndex(s, ")")
	if idx < 0 || idx+2 >= len(s) {
		return 0
	}
	fields := strings.Fields(s[idx+2:])
	// Field 22 in /proc/pid/stat is starttime; after comm extraction it's index 19.
	if len(fields) < 20 {
		return 0
	}
	v, err := fmt.Sscanf(fields[19], "%d", new(int64))
	if err != nil || v != 1 {
		return 0
	}
	var ns int64
	fmt.Sscanf(fields[19], "%d", &ns)
	return ns
}

// IsOurProcess checks if the PID is alive AND has the same start time as when we spawned it.
// This prevents operating on a recycled PID.
func IsOurProcess(pid int, expectedStartTime int64) bool {
	if !IsAlive(pid) {
		return false
	}
	if expectedStartTime == 0 {
		return true // no start time recorded, fall back to PID-only check
	}
	actual := procStartTime(pid)
	if actual == 0 {
		return true // can't read /proc, fall back to PID-only check
	}
	return actual == expectedStartTime
}
