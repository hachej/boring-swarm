package monitor

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"boring-swarm/cli/bsw/process"
)

// State represents the lifecycle state of a worker process.
type State string

const (
	Running   State = "running"
	Stale     State = "stale"
	ExitedOK  State = "exited(0)"
	ExitedErr State = "exited(1)"
	Dead      State = "dead"
	Orphan    State = "orphan"
)

// Status is the full health snapshot for a single worker.
type Status struct {
	WorkerID      string `json:"worker_id"`
	Persona       string `json:"persona"`
	Mode          string `json:"mode"`
	PID           int    `json:"pid"`
	Pane          string `json:"pane,omitempty"`
	State         State  `json:"state"`
	ExitCode      *int   `json:"exit_code"`
	StartedAt     string `json:"started_at"`
	Uptime        string `json:"uptime"`
	LastActivity  string `json:"last_activity"`
	Stale         bool   `json:"stale"`
	Log           string `json:"log"`
	AgentMailName string `json:"agent_mail_name,omitempty"`
}

// CheckPID determines whether a process is alive using kill(pid, 0) and checks
// /proc/<pid>/status for zombie state.
func CheckPID(pid int) (alive bool, exitCode *int) {
	if pid <= 0 {
		code := 1
		return false, &code
	}
	err := syscall.Kill(pid, 0)
	if err != nil {
		// Process is not reachable — treat as dead.
		code := 1
		return false, &code
	}

	// Process exists in the kernel. Check if it's a zombie.
	if isZombie(pid) {
		code := 1
		return false, &code
	}

	return true, nil
}

// isZombie reads /proc/<pid>/status and returns true if the process state is Z
// (zombie). Returns false on any read error (conservative: assume not zombie).
func isZombie(pid int) bool {
	f, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "State:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[1] == "Z" {
				return true
			}
			return false
		}
	}
	return false
}

// CheckTmuxPane verifies that a tmux pane exists and returns the PID of the
// process running inside it.
func CheckTmuxPane(pane string) (exists bool, panePID int) {
	out, err := exec.Command("tmux", "list-panes", "-t", pane, "-F", "#{pane_pid}").Output()
	if err != nil {
		return false, 0
	}

	line := strings.TrimSpace(string(out))
	if line == "" {
		return false, 0
	}

	// Take the first line in case multiple lines are returned.
	first := strings.Split(line, "\n")[0]
	pid, err := strconv.Atoi(strings.TrimSpace(first))
	if err != nil {
		return false, 0
	}

	return true, pid
}

// CheckWorker builds a full Status for the given WorkerEntry. It dispatches to
// background or tmux checking logic and computes uptime, last activity, and
// staleness from the log file mtime.
func CheckWorker(entry process.WorkerEntry, stallTimeout time.Duration) Status {
	s := Status{
		WorkerID:      entry.WorkerID,
		Persona:       entry.Persona,
		Mode:          entry.Mode,
		PID:           entry.PID,
		Pane:          entry.Pane,
		StartedAt:     entry.StartedAt,
		Log:           entry.Log,
		AgentMailName: entry.AgentMailName,
	}

	// Compute uptime from StartedAt.
	s.Uptime = computeUptime(entry.StartedAt)

	// Compute last activity from log file mtime.
	lastAct, lastActDur := computeLastActivity(entry.Log)
	s.LastActivity = lastAct

	// Determine process state.
	switch entry.Mode {
	case "tmux":
		s.State, s.ExitCode = checkTmuxWorker(entry)
	default: // "bg" or anything else
		s.State, s.ExitCode = checkBgWorker(entry)
	}

	// Compute staleness: only relevant if the process is running.
	if s.State == Running && stallTimeout > 0 && lastActDur > stallTimeout {
		s.State = Stale
		s.Stale = true
	}

	return s
}

// checkBgWorker checks a background process by PID with start time verification.
func checkBgWorker(entry process.WorkerEntry) (State, *int) {
	alive, exitCode := CheckPID(entry.PID)
	if !alive {
		if exitCode != nil {
			return ExitedErr, exitCode
		}
		return Dead, nil
	}
	// PID is alive — verify it's the same process we spawned (not a recycled PID).
	if entry.StartTimeNs > 0 {
		actual := process.ProcStartTime(entry.PID)
		if actual != 0 && actual != entry.StartTimeNs {
			code := 1
			return Dead, &code // original process is gone, PID was recycled
		}
	}
	return Running, nil
}

// checkTmuxWorker checks a tmux-based worker: first verifies the pane exists,
// then checks the process inside the pane.
func checkTmuxWorker(entry process.WorkerEntry) (State, *int) {
	if entry.Pane == "" {
		return Dead, nil
	}

	paneExists, panePID := CheckTmuxPane(entry.Pane)
	if !paneExists {
		// Pane is gone. Check if original PID is still alive (orphan).
		alive, _ := CheckPID(entry.PID)
		if alive {
			return Orphan, nil
		}
		code := 1
		return Dead, &code
	}

	// Pane exists. Check the process inside it.
	alive, exitCode := CheckPID(panePID)
	if alive {
		return Running, nil
	}

	// Pane exists but process inside is dead — could be normal exit.
	if exitCode != nil && *exitCode == 0 {
		return ExitedOK, exitCode
	}
	return ExitedErr, exitCode
}


// computeUptime parses a StartedAt timestamp (RFC3339) and returns a
// human-readable duration string.
func computeUptime(startedAt string) string {
	t, err := time.Parse(time.RFC3339, startedAt)
	if err != nil {
		return "unknown"
	}
	d := time.Since(t)
	return formatDuration(d)
}

// computeLastActivity stats the log file and returns a human-readable "Xs ago"
// string and the raw duration. Returns ("unknown", 0) if the file cannot be
// stat'd.
func computeLastActivity(logPath string) (string, time.Duration) {
	if logPath == "" {
		return "unknown", 0
	}
	info, err := os.Stat(logPath)
	if err != nil {
		return "unknown", 0
	}
	d := time.Since(info.ModTime())
	return formatDuration(d) + " ago", d
}

// formatDuration returns a concise human-readable duration.
func formatDuration(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		h := int(d.Hours())
		m := int(d.Minutes()) % 60
		if m == 0 {
			return fmt.Sprintf("%dh", h)
		}
		return fmt.Sprintf("%dh%dm", h, m)
	default:
		days := int(d.Hours()) / 24
		h := int(d.Hours()) % 24
		if h == 0 {
			return fmt.Sprintf("%dd", days)
		}
		return fmt.Sprintf("%dd%dh", days, h)
	}
}
