package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

type AttemptStore struct {
	projectRoot string
}

type attemptFile struct {
	UpdatedAt string         `json:"updated_at"`
	Attempts  map[string]int `json:"attempts"`
}

func NewAttemptStore(projectRoot string) AttemptStore {
	return AttemptStore{projectRoot: projectRoot}
}

func (s AttemptStore) path() string {
	return filepath.Join(s.projectRoot, ".bsw", "attempts.json")
}

func (s AttemptStore) load() attemptFile {
	b, err := os.ReadFile(s.path())
	if err != nil {
		return attemptFile{Attempts: map[string]int{}}
	}
	var a attemptFile
	if err := json.Unmarshal(b, &a); err != nil {
		return attemptFile{Attempts: map[string]int{}}
	}
	if a.Attempts == nil {
		a.Attempts = map[string]int{}
	}
	return a
}

func (s AttemptStore) save(a attemptFile) error {
	if err := os.MkdirAll(filepath.Join(s.projectRoot, ".bsw"), 0o755); err != nil {
		return err
	}
	a.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	b, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	p := s.path()
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

func (s AttemptStore) Next(beadID string) (int, error) {
	a := s.load()
	a.Attempts[beadID] = a.Attempts[beadID] + 1
	if err := s.save(a); err != nil {
		return 0, err
	}
	return a.Attempts[beadID], nil
}
