package persona

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"
)

// Persona defines an agent persona loaded from a TOML file.
type Persona struct {
	Provider  string `toml:"provider"`
	Model     string `toml:"model"`
	Prompt    string `toml:"prompt"`      // path to prompt .md file
	WorkLabel string `toml:"work_label"`
	Effort    string `toml:"effort"`      // low|medium|high, optional
}

// Load reads a single persona from a TOML file.
func Load(path string) (Persona, error) {
	var p Persona
	data, err := os.ReadFile(path)
	if err != nil {
		return p, fmt.Errorf("persona: read %s: %w", path, err)
	}
	if err := toml.Unmarshal(data, &p); err != nil {
		return p, fmt.Errorf("persona: parse %s: %w", path, err)
	}
	return p, nil
}

// LoadDir reads all *.toml files from a directory and returns a map keyed by
// filename without extension.
func LoadDir(dir string) (map[string]Persona, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("persona: read dir %s: %w", dir, err)
	}

	personas := make(map[string]Persona)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".toml") {
			continue
		}
		p, err := Load(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		name := strings.TrimSuffix(e.Name(), ".toml")
		personas[name] = p
	}
	return personas, nil
}

// PlaybookEntry defines how many instances of a persona to run.
type PlaybookEntry struct {
	Count int `yaml:"count"`
}

// Hooks defines optional shell commands to run before/after a playbook run.
type Hooks struct {
	BeforeRun string `yaml:"before_run"`
	AfterRun  string `yaml:"after_run"`
}

// Playbook defines a named collection of personas to run together.
type Playbook struct {
	Name         string                   `yaml:"name"`
	Personas     map[string]PlaybookEntry `yaml:"personas"`
	Hooks        Hooks                    `yaml:"hooks"`
	StallTimeout string                   `yaml:"stall_timeout"` // e.g. "10m"
}

// LoadPlaybook reads a YAML playbook file.
func LoadPlaybook(path string) (Playbook, error) {
	var pb Playbook
	data, err := os.ReadFile(path)
	if err != nil {
		return pb, fmt.Errorf("persona: read playbook %s: %w", path, err)
	}
	if err := yaml.Unmarshal(data, &pb); err != nil {
		return pb, fmt.Errorf("persona: parse playbook %s: %w", path, err)
	}
	return pb, nil
}
