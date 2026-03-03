package status

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

type AttentionItem struct {
	BeadID          string `json:"bead_id"`
	Reason          string `json:"reason"`
	SuggestedAction string `json:"suggested_action"`
	Details         string `json:"details,omitempty"`
	At              string `json:"at"`
}

type AttentionStore struct {
	projectRoot string
}

type attentionFile struct {
	Items []AttentionItem `json:"items"`
}

func NewAttentionStore(projectRoot string) AttentionStore {
	return AttentionStore{projectRoot: projectRoot}
}

func (s AttentionStore) path() string {
	return filepath.Join(s.projectRoot, ".bsw", "attention.json")
}

func (s AttentionStore) Load() ([]AttentionItem, error) {
	b, err := os.ReadFile(s.path())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var f attentionFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	return f.Items, nil
}

func (s AttentionStore) save(items []AttentionItem) error {
	if err := os.MkdirAll(filepath.Join(s.projectRoot, ".bsw"), 0o755); err != nil {
		return err
	}
	f := attentionFile{Items: items}
	b, err := json.MarshalIndent(f, "", "  ")
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

func (s AttentionStore) Upsert(item AttentionItem) error {
	_, err := s.UpsertChanged(item)
	return err
}

func (s AttentionStore) UpsertChanged(item AttentionItem) (bool, error) {
	items, _ := s.Load()
	if item.At == "" {
		item.At = time.Now().UTC().Format(time.RFC3339)
	}
	updated := false
	for i := range items {
		if items[i].BeadID == item.BeadID && items[i].Reason == item.Reason {
			// Avoid rewriting the same attention payload each cycle.
			if items[i].SuggestedAction == item.SuggestedAction && items[i].Details == item.Details {
				return false, nil
			}
			items[i] = item
			updated = true
			break
		}
	}
	if !updated {
		items = append(items, item)
	}
	if err := s.save(items); err != nil {
		return false, err
	}
	return true, nil
}

func (s AttentionStore) Clear(beadID, reason string) error {
	_, err := s.ClearChanged(beadID, reason)
	return err
}

func (s AttentionStore) ClearChanged(beadID, reason string) (bool, error) {
	items, _ := s.Load()
	out := make([]AttentionItem, 0, len(items))
	changed := false
	for _, it := range items {
		if it.BeadID == beadID && it.Reason == reason {
			changed = true
			continue
		}
		out = append(out, it)
	}
	if !changed {
		return false, nil
	}
	if err := s.save(out); err != nil {
		return false, err
	}
	return true, nil
}
