package monitor

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"boring-swarm/cli/bsw/process"
)

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		name string
		d    time.Duration
		want string
	}{
		{"zero", 0, "0s"},
		{"seconds", 45 * time.Second, "45s"},
		{"one minute", time.Minute, "1m"},
		{"minutes", 5*time.Minute + 30*time.Second, "5m"},
		{"one hour", time.Hour, "1h"},
		{"hours and minutes", 2*time.Hour + 15*time.Minute, "2h15m"},
		{"hours exact", 3 * time.Hour, "3h"},
		{"one day", 24 * time.Hour, "1d"},
		{"days and hours", 2*24*time.Hour + 5*time.Hour, "2d5h"},
		{"days exact", 7 * 24 * time.Hour, "7d"},
		{"negative", -30 * time.Second, "30s"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatDuration(tt.d)
			if got != tt.want {
				t.Errorf("formatDuration(%v) = %q, want %q", tt.d, got, tt.want)
			}
		})
	}
}

func TestComputeUptime(t *testing.T) {
	// Valid RFC3339 timestamp from 1 hour ago
	oneHourAgo := time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339)
	result := computeUptime(oneHourAgo)
	if result == "unknown" {
		t.Errorf("computeUptime(%q) = %q, want valid duration", oneHourAgo, result)
	}

	// Invalid timestamp
	result = computeUptime("not-a-date")
	if result != "unknown" {
		t.Errorf("computeUptime(invalid) = %q, want %q", result, "unknown")
	}

	// Empty string
	result = computeUptime("")
	if result != "unknown" {
		t.Errorf("computeUptime(\"\") = %q, want %q", result, "unknown")
	}
}

func TestComputeLastActivity(t *testing.T) {
	// Empty path
	desc, dur := computeLastActivity("")
	if desc != "unknown" || dur != 0 {
		t.Errorf("computeLastActivity(\"\") = (%q, %v), want (\"unknown\", 0)", desc, dur)
	}

	// Non-existent file
	desc, dur = computeLastActivity("/tmp/nonexistent-file-xyz-12345.log")
	if desc != "unknown" || dur != 0 {
		t.Errorf("computeLastActivity(nonexistent) = (%q, %v), want (\"unknown\", 0)", desc, dur)
	}

	// Real file
	tmpFile := filepath.Join(t.TempDir(), "test.log")
	if err := os.WriteFile(tmpFile, []byte("test"), 0o644); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}
	desc, dur = computeLastActivity(tmpFile)
	if desc == "unknown" {
		t.Error("computeLastActivity(real file) should not return 'unknown'")
	}
	if dur < 0 || dur > 5*time.Second {
		t.Errorf("computeLastActivity(just-created file) duration = %v, expected < 5s", dur)
	}
}

func TestCheckPID(t *testing.T) {
	// Our own PID should be alive
	alive, exitCode := CheckPID(os.Getpid())
	if !alive {
		t.Error("CheckPID(self) should be alive")
	}
	if exitCode != nil {
		t.Errorf("CheckPID(self) exitCode should be nil, got %d", *exitCode)
	}

	// PID 0 should not be alive
	alive, exitCode = CheckPID(0)
	if alive {
		t.Error("CheckPID(0) should not be alive")
	}
	if exitCode == nil || *exitCode != 1 {
		t.Error("CheckPID(0) should return exitCode=1")
	}

	// Negative PID should not be alive
	alive, exitCode = CheckPID(-1)
	if alive {
		t.Error("CheckPID(-1) should not be alive")
	}

	// Very large PID that likely doesn't exist
	alive, _ = CheckPID(4194304) // max PID on most linux systems
	// Don't assert — it might exist in some environments
	_ = alive
}

func TestCheckWorkerStaleness(t *testing.T) {
	// Create a log file with old mtime to simulate stale worker
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "stale.log")
	if err := os.WriteFile(logFile, []byte("log output"), 0o644); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}
	// Set mtime to 20 minutes ago
	oldTime := time.Now().Add(-20 * time.Minute)
	if err := os.Chtimes(logFile, oldTime, oldTime); err != nil {
		t.Fatalf("Chtimes error: %v", err)
	}

	entry := process.WorkerEntry{
		WorkerID:  "stale-worker",
		Persona:   "default",
		Mode:      "bg",
		PID:       os.Getpid(), // Use our own PID so it shows as "running"
		StartedAt: time.Now().Add(-30 * time.Minute).UTC().Format(time.RFC3339),
		Log:       logFile,
	}

	// With a 10-minute stall timeout, this should be Stale
	status := CheckWorker(entry, 10*time.Minute)
	if status.State != Stale {
		t.Errorf("CheckWorker with old log = state %q, want %q", status.State, Stale)
	}
	if !status.Stale {
		t.Error("CheckWorker with old log should have Stale=true")
	}
}

func TestCheckWorkerRunning(t *testing.T) {
	// Create a fresh log file
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "fresh.log")
	if err := os.WriteFile(logFile, []byte("log output"), 0o644); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	entry := process.WorkerEntry{
		WorkerID:  "fresh-worker",
		Persona:   "default",
		Mode:      "bg",
		PID:       os.Getpid(), // Use our own PID
		StartedAt: time.Now().Add(-5 * time.Minute).UTC().Format(time.RFC3339),
		Log:       logFile,
	}

	status := CheckWorker(entry, 10*time.Minute)
	if status.State != Running {
		t.Errorf("CheckWorker with fresh log = state %q, want %q", status.State, Running)
	}
}

func TestCheckWorkerDeadProcess(t *testing.T) {
	entry := process.WorkerEntry{
		WorkerID:  "dead-worker",
		Persona:   "default",
		Mode:      "bg",
		PID:       999999999, // PID that doesn't exist
		StartedAt: time.Now().Add(-5 * time.Minute).UTC().Format(time.RFC3339),
	}

	status := CheckWorker(entry, 10*time.Minute)
	if status.State != ExitedErr {
		t.Errorf("CheckWorker with dead PID = state %q, want %q", status.State, ExitedErr)
	}
}

func TestCheckWorkerNoStallTimeout(t *testing.T) {
	// With 0 stall timeout, even a stale log shouldn't trigger staleness
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "old.log")
	if err := os.WriteFile(logFile, []byte("log output"), 0o644); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}
	oldTime := time.Now().Add(-1 * time.Hour)
	os.Chtimes(logFile, oldTime, oldTime)

	entry := process.WorkerEntry{
		WorkerID:  "no-timeout-worker",
		Persona:   "default",
		Mode:      "bg",
		PID:       os.Getpid(),
		StartedAt: time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339),
		Log:       logFile,
	}

	status := CheckWorker(entry, 0) // stall timeout disabled
	if status.State != Running {
		t.Errorf("CheckWorker with 0 timeout = state %q, want %q", status.State, Running)
	}
}

func TestStateConstants(t *testing.T) {
	// Verify state string values match expected output format
	if Running != "running" {
		t.Errorf("Running = %q", Running)
	}
	if Stale != "stale" {
		t.Errorf("Stale = %q", Stale)
	}
	if ExitedOK != "exited(0)" {
		t.Errorf("ExitedOK = %q", ExitedOK)
	}
	if ExitedErr != "exited(1)" {
		t.Errorf("ExitedErr = %q", ExitedErr)
	}
	if Dead != "dead" {
		t.Errorf("Dead = %q", Dead)
	}
	if Orphan != "orphan" {
		t.Errorf("Orphan = %q", Orphan)
	}
}
