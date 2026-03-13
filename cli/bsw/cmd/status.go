package cmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"boring-swarm/cli/bsw/monitor"
	"boring-swarm/cli/bsw/process"
)

// projectStatus collects worker statuses for a single project root.
// Pure function — no output, no side effects.
func projectStatus(root string) ([]monitor.Status, error) {
	reg := process.NewRegistry(root)
	entries, err := reg.LoadAll()
	if err != nil {
		return nil, err
	}

	stallTimeout := 10 * time.Minute
	statuses := make([]monitor.Status, 0, len(entries))
	for _, e := range entries {
		me := monitor.WorkerEntry{
			WorkerID:      e.WorkerID,
			Persona:       e.Persona,
			Mode:          e.Mode,
			PID:           e.PID,
			Pane:          e.Pane,
			StartedAt:     e.StartedAt,
			StartTimeNs:   e.StartTimeNs,
			Log:           e.Log,
			AgentMailName: e.AgentMailName,
		}
		statuses = append(statuses, monitor.CheckWorker(me, stallTimeout))
	}
	return statuses, nil
}

func runStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "output as JSON")
	project := fs.String("project", ".", "project root directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	root, err := projectRootFromFlag(*project)
	if err != nil {
		return err
	}

	statuses, err := projectStatus(root)
	if err != nil {
		return err
	}

	now := time.Now()
	fmt.Fprintf(os.Stderr, "--- check %s | next %s ---\n", now.Format("15:04:05"), now.Add(30*time.Second).Format("15:04:05"))

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(statuses)
	}

	if len(statuses) == 0 {
		fmt.Println("No active workers")
		return nil
	}

	fmt.Printf("Workers: %d\n\n", len(statuses))
	for _, s := range statuses {
		staleTag := ""
		if s.Stale {
			staleTag = " [STALE]"
		}
		amTag := ""
		if s.AgentMailName != "" {
			amTag = fmt.Sprintf(" mail=%s", s.AgentMailName)
		}
		fmt.Printf("  %-12s %-10s %-6s %-10s pid=%-6d up=%-8s activity=%-10s%s%s\n",
			s.WorkerID, s.Persona, s.Mode, s.State, s.PID, s.Uptime, s.LastActivity, staleTag, amTag)
	}
	return nil
}
