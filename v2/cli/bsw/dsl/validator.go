package dsl

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"boring-swarm/v2/cli/bsw/agent"
)

var eventKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]*:[a-z][a-z0-9_-]*$`)

func Validate(spec FlowSpec) error {
	if spec.Version != Version {
		return fmt.Errorf("version must be %d", Version)
	}
	if strings.TrimSpace(spec.Name) == "" {
		return fmt.Errorf("name is required")
	}
	if strings.TrimSpace(spec.Source.Label) == "" {
		return fmt.Errorf("source.label is required")
	}

	if spec.Workers.Count <= 0 {
		return fmt.Errorf("workers.count must be > 0")
	}
	provider := agent.NormalizeProvider(spec.Workers.Provider)
	if provider != "codex" && provider != "claude" {
		return fmt.Errorf("workers.provider must be codex or claude (aliases: claude-code, ccc)")
	}
	if strings.TrimSpace(spec.Workers.Model) == "" {
		return fmt.Errorf("workers.model is required")
	}
	prompt := strings.TrimSpace(spec.Workers.Prompt)
	if prompt == "" {
		return fmt.Errorf("workers.prompt is required")
	}
	if filepath.IsAbs(prompt) {
		return fmt.Errorf("workers.prompt must be relative to .bsw")
	}

	if len(spec.Transitions) == 0 {
		return fmt.Errorf("transitions must not be empty")
	}
	seen := map[string]struct{}{}
	for raw, target := range spec.Transitions {
		e := strings.ToLower(strings.TrimSpace(raw))
		if !eventKeyPattern.MatchString(e) {
			return fmt.Errorf("invalid transition key %q; expected role:event format", raw)
		}
		if strings.TrimSpace(target) == "" {
			return fmt.Errorf("transition target for %q is empty", raw)
		}
		if _, ok := seen[e]; ok {
			return fmt.Errorf("duplicate transition key after canonicalization: %q", e)
		}
		seen[e] = struct{}{}
	}

	if _, err := spec.TimeoutDuration(); err != nil {
		return err
	}
	return nil
}
