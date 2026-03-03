package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type CursorStore struct {
	projectRoot string
}

type cursorFile struct {
	BeadID      string `json:"bead_id"`
	LastComment int64  `json:"last_processed_comment_id"`
	UpdatedAt   string `json:"updated_at"`
}

func NewCursorStore(projectRoot string) CursorStore {
	return CursorStore{projectRoot: projectRoot}
}

func (s CursorStore) dir() string {
	return filepath.Join(s.projectRoot, ".bsw", "cursors")
}

func (s CursorStore) Ensure() error {
	return os.MkdirAll(s.dir(), 0o755)
}

func (s CursorStore) path(beadID string) string {
	return filepath.Join(s.dir(), strings.TrimSpace(beadID)+".json")
}

func (s CursorStore) Get(beadID string) int64 {
	b, err := os.ReadFile(s.path(beadID))
	if err != nil {
		return 0
	}
	var c cursorFile
	if err := json.Unmarshal(b, &c); err != nil {
		return 0
	}
	return c.LastComment
}

func (s CursorStore) Set(beadID string, id int64) error {
	if err := s.Ensure(); err != nil {
		return err
	}
	c := cursorFile{BeadID: strings.TrimSpace(beadID), LastComment: id, UpdatedAt: time.Now().UTC().Format(time.RFC3339)}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	p := s.path(beadID)
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}
