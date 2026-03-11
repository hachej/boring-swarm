package cmd

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"boring-swarm/cli/bsw/monitor"
)

const defaultProjectsFile = ".bsw-projects"

// projectResult holds the status result for one project.
type projectResult struct {
	Project  string           `json:"project"`
	Statuses []monitor.Status `json:"workers,omitempty"`
	Error    string           `json:"error,omitempty"`
}

// projectSummary is a concise per-project summary.
type projectSummary struct {
	Project string
	Running int
	Stale   int
	Dead    int
	Total   int
	Err     string
}

func runMultiStatus(args []string) error {
	fs := flag.NewFlagSet("multi-status", flag.ContinueOnError)
	config := fs.String("config", "", "projects file (default: ~/.bsw-projects)")
	discover := fs.String("discover", "", "discover projects under this root (finds .bsw/ dirs)")
	asJSON := fs.Bool("json", false, "output as JSON")
	summary := fs.Bool("summary", true, "show concise summary (default; --summary=false for full)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	projects, err := resolveProjects(*config, *discover)
	if err != nil {
		return err
	}
	if len(projects) == 0 {
		fmt.Println("No projects found. Use --config or --discover, or create ~/.bsw-projects")
		return nil
	}

	// Fetch status concurrently with bounded parallelism
	results := make([]projectResult, len(projects))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8) // max 8 concurrent

	for i, p := range projects {
		wg.Add(1)
		go func(idx int, proj string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			statuses, err := projectStatus(proj)
			if err != nil {
				results[idx] = projectResult{Project: proj, Error: err.Error()}
			} else {
				results[idx] = projectResult{Project: proj, Statuses: statuses}
			}
		}(i, p)
	}
	wg.Wait()

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(results)
	}

	if *summary {
		return printSummary(results)
	}
	return printFull(results)
}

func printSummary(results []projectResult) error {
	hasIssues := false
	for _, r := range results {
		name := filepath.Base(r.Project)
		if r.Error != "" {
			fmt.Printf("  %-30s  ERROR: %s\n", name, r.Error)
			hasIssues = true
			continue
		}
		s := summarize(r.Statuses)
		tag := ""
		if s.Stale > 0 || s.Dead > 0 {
			tag = " !!"
			hasIssues = true
		}
		if s.Total == 0 {
			fmt.Printf("  %-30s  (no workers)\n", name)
		} else {
			fmt.Printf("  %-30s  %d running, %d stale, %d dead  (total %d)%s\n",
				name, s.Running, s.Stale, s.Dead, s.Total, tag)
		}
	}
	if hasIssues {
		return fmt.Errorf("issues found in one or more projects")
	}
	return nil
}

func printFull(results []projectResult) error {
	for i, r := range results {
		if i > 0 {
			fmt.Println()
		}
		fmt.Printf("=== %s ===\n", r.Project)
		if r.Error != "" {
			fmt.Printf("  ERROR: %s\n", r.Error)
			continue
		}
		if len(r.Statuses) == 0 {
			fmt.Println("  No active workers")
			continue
		}
		for _, s := range r.Statuses {
			staleTag := ""
			if s.Stale {
				staleTag = " [STALE]"
			}
			fmt.Printf("  %-12s %-10s %-6s %-10s pid=%-6d up=%-8s activity=%-10s%s\n",
				s.BeadID, s.Persona, s.Mode, s.State, s.PID, s.Uptime, s.LastActivity, staleTag)
		}
	}
	return nil
}

func summarize(statuses []monitor.Status) projectSummary {
	s := projectSummary{Total: len(statuses)}
	for _, st := range statuses {
		switch st.State {
		case monitor.Running:
			s.Running++
		case monitor.Stale:
			s.Stale++
		default:
			s.Dead++
		}
	}
	return s
}

// resolveProjects returns deduplicated, absolute project paths.
func resolveProjects(configPath, discoverRoot string) ([]string, error) {
	var raw []string

	if discoverRoot != "" {
		found, err := discoverProjects(discoverRoot)
		if err != nil {
			return nil, fmt.Errorf("discover: %w", err)
		}
		raw = append(raw, found...)
	}

	if configPath == "" {
		home, err := os.UserHomeDir()
		if err == nil {
			configPath = filepath.Join(home, defaultProjectsFile)
		}
	}
	if configPath != "" {
		fromFile, err := readProjectsFile(configPath)
		if err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("read %s: %w", configPath, err)
		}
		raw = append(raw, fromFile...)
	}

	// Deduplicate by resolved absolute path
	seen := make(map[string]struct{})
	var out []string
	for _, p := range raw {
		abs, err := filepath.Abs(p)
		if err != nil {
			continue
		}
		real, err := filepath.EvalSymlinks(abs)
		if err != nil {
			real = abs
		}
		if _, ok := seen[real]; ok {
			continue
		}
		seen[real] = struct{}{}
		out = append(out, real)
	}
	return out, nil
}

// discoverProjects walks up to 2 levels deep looking for .bsw/ directories.
func discoverProjects(root string) ([]string, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	var found []string
	entries, err := os.ReadDir(abs)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		candidate := filepath.Join(abs, e.Name())
		if hasBSWDir(candidate) {
			found = append(found, candidate)
		}
		// Check one level deeper
		sub, err := os.ReadDir(candidate)
		if err != nil {
			continue
		}
		for _, s := range sub {
			if !s.IsDir() {
				continue
			}
			subCandidate := filepath.Join(candidate, s.Name())
			if hasBSWDir(subCandidate) {
				found = append(found, subCandidate)
			}
		}
	}
	return found, nil
}

func hasBSWDir(dir string) bool {
	info, err := os.Stat(filepath.Join(dir, ".bsw"))
	return err == nil && info.IsDir()
}

func readProjectsFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var projects []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		projects = append(projects, line)
	}
	return projects, scanner.Err()
}
