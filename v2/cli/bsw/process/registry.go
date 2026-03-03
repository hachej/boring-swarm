package process

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type Registry struct {
	projectRoot string
}

type WorkerRuntime struct {
	BeadID                 string   `json:"bead_id"`
	Role                   string   `json:"role"`
	PID                    int      `json:"pid"`
	Provider               string   `json:"provider"`
	SessionRef             string   `json:"session_ref,omitempty"`
	ResumeCommand          string   `json:"resume_command,omitempty"`
	AgentName              string   `json:"agent_name"`
	AssignmentToken        string   `json:"assignment_token"`
	SourceLabel            string   `json:"source_label"`
	AllowedTransitions     []string `json:"allowed_transitions"`
	RunID                  string   `json:"run_id"`
	Attempt                int      `json:"attempt"`
	StartedAt              string   `json:"started_at"`
	LastProgressTS         string   `json:"last_progress_ts,omitempty"`
	LastProcessedCommentID int64    `json:"last_processed_comment_id,omitempty"`
	LastStateEvent         string   `json:"last_state_event,omitempty"`
	ActivityState          string   `json:"activity_state,omitempty"`
	ActivityReason         string   `json:"activity_reason,omitempty"`
	ProcessLogPath         string   `json:"process_log_path,omitempty"`
	RuntimePayloadPath     string   `json:"runtime_payload_path,omitempty"`
	PromptPath             string   `json:"prompt_path,omitempty"`
	UpdatedAt              string   `json:"updated_at,omitempty"`
}

func NewRegistry(projectRoot string) Registry {
	return Registry{projectRoot: projectRoot}
}

func (r Registry) Ensure() error {
	return os.MkdirAll(r.dir(), 0o755)
}

func (r Registry) dir() string {
	return filepath.Join(r.projectRoot, ".bsw", "agents")
}

func (r Registry) path(beadID string) string {
	safe := strings.TrimSpace(beadID)
	return filepath.Join(r.dir(), safe+".json")
}

func (r Registry) Save(rt WorkerRuntime) error {
	if strings.TrimSpace(rt.BeadID) == "" {
		return fmt.Errorf("registry save: bead_id required")
	}
	if err := r.Ensure(); err != nil {
		return err
	}
	rt.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	data, err := json.MarshalIndent(rt, "", "  ")
	if err != nil {
		return err
	}
	p := r.path(rt.BeadID)
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

func (r Registry) Delete(beadID string) error {
	err := os.Remove(r.path(beadID))
	if err == nil || os.IsNotExist(err) {
		return nil
	}
	return err
}

func (r Registry) Load(beadID string) (WorkerRuntime, error) {
	b, err := os.ReadFile(r.path(beadID))
	if err != nil {
		return WorkerRuntime{}, err
	}
	var rt WorkerRuntime
	if err := json.Unmarshal(b, &rt); err != nil {
		return WorkerRuntime{}, err
	}
	return rt, nil
}

func (r Registry) LoadAll() ([]WorkerRuntime, error) {
	if err := r.Ensure(); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(r.dir())
	if err != nil {
		return nil, err
	}
	out := make([]WorkerRuntime, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(r.dir(), e.Name())
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var rt WorkerRuntime
		if err := json.Unmarshal(b, &rt); err != nil {
			continue
		}
		if strings.TrimSpace(rt.BeadID) == "" {
			continue
		}
		out = append(out, rt)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].BeadID < out[j].BeadID })
	return out, nil
}
