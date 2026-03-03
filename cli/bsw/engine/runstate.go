package engine

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type RunState struct {
	RunID     string `json:"run_id"`
	Flow      string `json:"flow"`
	FlowName  string `json:"flow_name,omitempty"`
	Mode      string `json:"mode"`
	StartedAt string `json:"started_at"`
	PID       int    `json:"pid,omitempty"`
	Status    string `json:"status"`
}

func runStatePath(projectRoot string) string {
	return filepath.Join(projectRoot, ".bsw", "run.json")
}

func NewRunID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return "run-" + time.Now().UTC().Format("20060102-150405") + "-" + hex.EncodeToString(b)
}

func SaveRunState(projectRoot string, rs RunState) error {
	if err := os.MkdirAll(filepath.Join(projectRoot, ".bsw"), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(rs, "", "  ")
	if err != nil {
		return err
	}
	p := runStatePath(projectRoot)
	tmp := fmt.Sprintf("%s.%d.tmp", p, os.Getpid())
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

func LoadRunState(projectRoot string) (RunState, error) {
	b, err := os.ReadFile(runStatePath(projectRoot))
	if err != nil {
		return RunState{}, err
	}
	var rs RunState
	if err := json.Unmarshal(b, &rs); err != nil {
		return RunState{}, err
	}
	return rs, nil
}
