package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Event struct {
	Event           string `json:"event"`
	RunID           string `json:"run_id,omitempty"`
	Queue           string `json:"queue,omitempty"`
	BeadID          string `json:"bead_id,omitempty"`
	AssignmentToken string `json:"assignment_token,omitempty"`
	Agent           string `json:"agent,omitempty"`
	Provider        string `json:"provider,omitempty"`
	SessionRef      string `json:"session_ref,omitempty"`
	PID             int    `json:"pid,omitempty"`
	Value           string `json:"value,omitempty"`
	From            string `json:"from,omitempty"`
	To              string `json:"to,omitempty"`
	CommentID       int64  `json:"comment_id,omitempty"`
	Reason          string `json:"reason,omitempty"`
	SuggestedAction string `json:"suggested_action,omitempty"`
	Details         string `json:"details,omitempty"`
	TS              string `json:"ts"`
}

type Emitter struct {
	mu   sync.Mutex
	file *os.File
}

func NewEmitter(projectRoot, queueName, runID string) (*Emitter, error) {
	logDir := filepath.Join(projectRoot, ".bsw", "logs")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return nil, err
	}
	path := filepath.Join(logDir, fmt.Sprintf("%s-%s.jsonl", queueName, runID))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	return &Emitter{file: f}, nil
}

func (e *Emitter) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.file == nil {
		return nil
	}
	err := e.file.Close()
	e.file = nil
	return err
}

func (e *Emitter) Emit(ev Event) {
	ev.TS = time.Now().UTC().Format(time.RFC3339)
	line, err := json.Marshal(ev)
	if err != nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.file != nil {
		_, _ = e.file.Write(append(line, '\n'))
	}
	fmt.Println(string(line))
}
