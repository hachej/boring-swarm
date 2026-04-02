package process

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateWorkerID(t *testing.T) {
	tests := []struct {
		name    string
		id      string
		wantErr bool
	}{
		{"valid simple", "worker-1", false},
		{"valid dots", "worker.v2", false},
		{"valid underscores", "worker_abc", false},
		{"valid mixed", "my-worker.v1_alpha", false},
		{"empty", "", true},
		{"whitespace only", "   ", true},
		{"path traversal", "../etc/passwd", true},
		{"double dot", "worker..bad", true},
		{"slashes", "path/traversal", true},
		{"spaces", "worker name", true},
		{"special chars", "worker@host", true},
		{"backtick", "worker`cmd`", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateWorkerID(tt.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateWorkerID(%q) error = %v, wantErr %v", tt.id, err, tt.wantErr)
			}
		})
	}
}

func tempRegistry(t *testing.T) Registry {
	t.Helper()
	dir := t.TempDir()
	return NewRegistry(dir)
}

func TestRegistrySaveAndLoad(t *testing.T) {
	reg := tempRegistry(t)

	entry := WorkerEntry{
		WorkerID:  "test-worker",
		Persona:   "default",
		Provider:  "codex",
		Mode:      "bg",
		PID:       12345,
		StartedAt: "2026-04-01T10:00:00Z",
		Log:       "/tmp/test.log",
	}

	if err := reg.Save(entry); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	loaded, err := reg.Load("test-worker")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if loaded.WorkerID != entry.WorkerID {
		t.Errorf("WorkerID = %q, want %q", loaded.WorkerID, entry.WorkerID)
	}
	if loaded.Persona != entry.Persona {
		t.Errorf("Persona = %q, want %q", loaded.Persona, entry.Persona)
	}
	if loaded.PID != entry.PID {
		t.Errorf("PID = %d, want %d", loaded.PID, entry.PID)
	}
	if loaded.Mode != entry.Mode {
		t.Errorf("Mode = %q, want %q", loaded.Mode, entry.Mode)
	}
}

func TestRegistrySaveRejectsInvalidID(t *testing.T) {
	reg := tempRegistry(t)
	entry := WorkerEntry{WorkerID: "../bad"}
	if err := reg.Save(entry); err == nil {
		t.Error("Save() expected error for invalid worker ID, got nil")
	}
}

func TestRegistryDelete(t *testing.T) {
	reg := tempRegistry(t)

	entry := WorkerEntry{
		WorkerID: "to-delete",
		Persona:  "default",
		Provider: "claude",
		Mode:     "bg",
		PID:      99999,
	}
	if err := reg.Save(entry); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	if err := reg.Delete("to-delete"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	_, err := reg.Load("to-delete")
	if err == nil {
		t.Error("Load() after Delete() should return error")
	}
}

func TestRegistryDeleteNonExistent(t *testing.T) {
	reg := tempRegistry(t)
	if err := reg.Delete("nonexistent"); err != nil {
		t.Errorf("Delete() of nonexistent should be nil, got %v", err)
	}
}

func TestRegistryLoadAll(t *testing.T) {
	reg := tempRegistry(t)

	workers := []WorkerEntry{
		{WorkerID: "alpha", Persona: "default", Provider: "codex", Mode: "bg", PID: 1},
		{WorkerID: "beta", Persona: "default", Provider: "claude", Mode: "tmux", PID: 2},
		{WorkerID: "gamma", Persona: "default", Provider: "codex", Mode: "bg", PID: 3},
	}

	for _, w := range workers {
		if err := reg.Save(w); err != nil {
			t.Fatalf("Save(%s) error = %v", w.WorkerID, err)
		}
	}

	all, err := reg.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll() error = %v", err)
	}

	if len(all) != 3 {
		t.Fatalf("LoadAll() returned %d entries, want 3", len(all))
	}

	// LoadAll should be sorted by WorkerID
	if all[0].WorkerID != "alpha" || all[1].WorkerID != "beta" || all[2].WorkerID != "gamma" {
		t.Errorf("LoadAll() not sorted: got %s, %s, %s", all[0].WorkerID, all[1].WorkerID, all[2].WorkerID)
	}
}

func TestRegistryLoadAllSkipsNonJSON(t *testing.T) {
	reg := tempRegistry(t)

	// Save a valid entry
	if err := reg.Save(WorkerEntry{WorkerID: "valid", Persona: "p", Provider: "codex", Mode: "bg", PID: 1}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Write a non-JSON file
	if err := os.WriteFile(filepath.Join(reg.dir(), "readme.txt"), []byte("not json"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	// Write an invalid JSON file
	if err := os.WriteFile(filepath.Join(reg.dir(), "bad.json"), []byte("{invalid}"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	all, err := reg.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll() error = %v", err)
	}

	if len(all) != 1 {
		t.Errorf("LoadAll() returned %d entries, want 1 (should skip non-JSON and invalid)", len(all))
	}
}

func TestRegistryLoadAllSkipsEmptyWorkerID(t *testing.T) {
	reg := tempRegistry(t)

	// Save a valid entry
	if err := reg.Save(WorkerEntry{WorkerID: "valid", Persona: "p", Provider: "codex", Mode: "bg", PID: 1}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Write a JSON file with empty worker_id
	if err := os.WriteFile(filepath.Join(reg.dir(), "empty.json"), []byte(`{"worker_id":"","pid":1}`), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	all, err := reg.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll() error = %v", err)
	}

	if len(all) != 1 {
		t.Errorf("LoadAll() returned %d entries, want 1", len(all))
	}
}

func TestRegistryEnsureCreatesDir(t *testing.T) {
	dir := t.TempDir()
	reg := NewRegistry(dir)

	// dir/.bsw/workers/ should not exist yet
	workersDir := filepath.Join(dir, ".bsw", "workers")
	if _, err := os.Stat(workersDir); err == nil {
		t.Fatal("workers dir should not exist before Ensure()")
	}

	if err := reg.Ensure(); err != nil {
		t.Fatalf("Ensure() error = %v", err)
	}

	info, err := os.Stat(workersDir)
	if err != nil {
		t.Fatalf("workers dir should exist after Ensure(), got %v", err)
	}
	if !info.IsDir() {
		t.Error("workers path should be a directory")
	}
}
