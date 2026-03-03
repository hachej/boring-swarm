package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"boring-swarm/cli/bsw/process"
)

type ServiceProcess struct {
	FlowName  string `json:"flow_name"`
	PID       int    `json:"pid"`
	RunID     string `json:"run_id,omitempty"`
	StartedAt string `json:"started_at,omitempty"`
	Path      string `json:"-"`
}

func serviceRegistryDir(projectRoot string) string {
	return filepath.Join(projectRoot, ".bsw", "runtime", "services")
}

func serviceRegistryPath(projectRoot, flowName string) string {
	return filepath.Join(serviceRegistryDir(projectRoot), sanitizeFlowName(flowName)+".json")
}

func acquireServiceProcess(projectRoot, flowName, runID string, pid int) (func(), error) {
	if strings.TrimSpace(flowName) == "" {
		return nil, fmt.Errorf("service flow name required")
	}
	if pid <= 0 {
		return nil, fmt.Errorf("service pid required")
	}
	if err := os.MkdirAll(serviceRegistryDir(projectRoot), 0o755); err != nil {
		return nil, err
	}

	path := serviceRegistryPath(projectRoot, flowName)
	if existing, ok := readServiceProcess(path); ok && existing.PID > 0 && process.IsAlive(existing.PID) {
		return nil, fmt.Errorf("service for flow %q already running (pid=%d)", flowName, existing.PID)
	}

	entry := ServiceProcess{
		FlowName:  flowName,
		PID:       pid,
		RunID:     runID,
		StartedAt: time.Now().UTC().Format(time.RFC3339),
		Path:      path,
	}
	if err := writeServiceProcess(path, entry); err != nil {
		return nil, err
	}

	release := func() {
		current, ok := readServiceProcess(path)
		if ok && current.PID == pid {
			_ = os.Remove(path)
		}
	}
	return release, nil
}

func ListServiceProcesses(projectRoot string) ([]ServiceProcess, error) {
	dir := serviceRegistryDir(projectRoot)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	out := make([]ServiceProcess, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		sp, ok := readServiceProcess(path)
		if !ok {
			continue
		}
		sp.Path = path
		out = append(out, sp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FlowName < out[j].FlowName })
	return out, nil
}

func readServiceProcess(path string) (ServiceProcess, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return ServiceProcess{}, false
	}
	var sp ServiceProcess
	if err := json.Unmarshal(b, &sp); err != nil {
		return ServiceProcess{}, false
	}
	if strings.TrimSpace(sp.FlowName) == "" || sp.PID <= 0 {
		return ServiceProcess{}, false
	}
	return sp, true
}

func writeServiceProcess(path string, sp ServiceProcess) error {
	b, err := json.MarshalIndent(sp, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func sanitizeFlowName(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "service"
	}
	var b strings.Builder
	b.Grow(len(v))
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}
