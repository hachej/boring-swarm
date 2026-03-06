package dsl

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

const Version = 1

// FlowSpec is the queue DSL contract from v2/DSL.md.
type FlowSpec struct {
	Version     int               `yaml:"version"`
	Name        string            `yaml:"name"`
	Source      SourceSpec        `yaml:"source"`
	Workers     WorkerSpec        `yaml:"workers"`
	Transitions map[string]string `yaml:"transitions"`
	Timeout     string            `yaml:"timeout,omitempty"`
}

type SourceSpec struct {
	Label    string `yaml:"label"`
	Selector string `yaml:"selector,omitempty"`
}

type WorkerSpec struct {
	Count    int    `yaml:"count"`
	Provider string `yaml:"provider"`
	Model    string `yaml:"model"`
	Effort   string `yaml:"effort,omitempty"`
	Prompt   string `yaml:"prompt"`
}

func (f FlowSpec) CanonicalTransitions() map[string]string {
	out := make(map[string]string, len(f.Transitions))
	for k, v := range f.Transitions {
		out[canonicalEvent(k)] = strings.TrimSpace(v)
	}
	return out
}

func (f FlowSpec) AllowedEvents() []string {
	keys := make([]string, 0, len(f.Transitions))
	seen := map[string]struct{}{}
	for k := range f.Transitions {
		ck := canonicalEvent(k)
		if _, ok := seen[ck]; ok {
			continue
		}
		seen[ck] = struct{}{}
		keys = append(keys, ck)
	}
	sort.Strings(keys)
	return keys
}

func (f FlowSpec) TimeoutDuration() (time.Duration, error) {
	if strings.TrimSpace(f.Timeout) == "" {
		return 4 * time.Hour, nil
	}
	d, err := time.ParseDuration(strings.TrimSpace(f.Timeout))
	if err != nil {
		return 0, fmt.Errorf("invalid timeout %q: %w", f.Timeout, err)
	}
	return d, nil
}

func canonicalEvent(in string) string {
	return strings.ToLower(strings.TrimSpace(in))
}

func (s SourceSpec) CanonicalSelector() string {
	v := strings.ToLower(strings.TrimSpace(s.Selector))
	if v == "" {
		return "queue"
	}
	switch v {
	case "graph", "graph-aware", "robot-next":
		return "graph"
	default:
		return v
	}
}
