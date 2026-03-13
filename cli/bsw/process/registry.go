package process

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var validWorkerID = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

// ValidateWorkerID rejects worker IDs that could cause path traversal or other issues.
func ValidateWorkerID(id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("worker ID is empty")
	}
	if !validWorkerID.MatchString(id) {
		return fmt.Errorf("worker ID %q contains invalid characters (allowed: a-z A-Z 0-9 . _ -)", id)
	}
	if strings.Contains(id, "..") {
		return fmt.Errorf("worker ID %q contains '..'", id)
	}
	return nil
}

type WorkerEntry struct {
	WorkerID      string `json:"worker_id"`
	Persona       string `json:"persona"`
	Provider      string `json:"provider"`
	Mode          string `json:"mode"` // "tmux" | "bg"
	PID           int    `json:"pid"`
	Pane          string `json:"pane,omitempty"`
	StartedAt     string `json:"started_at"`
	StartTimeNs   int64  `json:"start_time_ns"` // process start time from /proc for PID reuse detection
	Log           string `json:"log"`
	AgentMailName string `json:"agent_mail_name,omitempty"` // Agent Mail identity
}

type Registry struct {
	projectRoot string
}

func NewRegistry(projectRoot string) Registry {
	return Registry{projectRoot: projectRoot}
}

func (r Registry) Ensure() error {
	return os.MkdirAll(r.dir(), 0o755)
}

func (r Registry) dir() string {
	return filepath.Join(r.projectRoot, ".bsw", "workers")
}

func (r Registry) path(workerID string) string {
	safe := strings.TrimSpace(workerID)
	return filepath.Join(r.dir(), safe+".json")
}

// IsActive returns true if a worker is registered and its process is alive.
func (r Registry) IsActive(workerID string) bool {
	e, err := r.Load(workerID)
	if err != nil {
		return false
	}
	return IsOurProcess(e.PID, e.StartTimeNs)
}

func (r Registry) Save(e WorkerEntry) error {
	if err := ValidateWorkerID(e.WorkerID); err != nil {
		return fmt.Errorf("registry save: %w", err)
	}
	if err := r.Ensure(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	p := r.path(e.WorkerID)
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

func (r Registry) Delete(workerID string) error {
	err := os.Remove(r.path(workerID))
	if err == nil || os.IsNotExist(err) {
		return nil
	}
	return err
}

func (r Registry) Load(workerID string) (WorkerEntry, error) {
	b, err := os.ReadFile(r.path(workerID))
	if err != nil {
		return WorkerEntry{}, err
	}
	var e WorkerEntry
	if err := json.Unmarshal(b, &e); err != nil {
		return WorkerEntry{}, err
	}
	return e, nil
}

func (r Registry) LoadAll() ([]WorkerEntry, error) {
	if err := r.Ensure(); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(r.dir())
	if err != nil {
		return nil, err
	}
	out := make([]WorkerEntry, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(r.dir(), e.Name()))
		if err != nil {
			continue
		}
		var we WorkerEntry
		if err := json.Unmarshal(b, &we); err != nil {
			continue
		}
		if strings.TrimSpace(we.WorkerID) == "" {
			continue
		}
		out = append(out, we)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].WorkerID < out[j].WorkerID })
	return out, nil
}
