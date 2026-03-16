package cmd

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"boring-swarm/cli/bsw/beads"
	"boring-swarm/cli/bsw/process"
)

func runStop(args []string) error {
	fs := flag.NewFlagSet("stop", flag.ContinueOnError)
	project := fs.String("project", ".", "project root directory")
	all := fs.Bool("all", false, "also stop the orchestrator")
	if err := fs.Parse(args); err != nil {
		return err
	}
	root, err := projectRootFromFlag(*project)
	if err != nil {
		return err
	}

	// Load orchestrator name so we skip it unless --all
	orchName := loadOrchestratorName(root)

	reg := process.NewRegistry(root)
	entries, err := reg.LoadAll()
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		fmt.Println("No active workers")
		return nil
	}

	client := beads.Client{Workdir: root}
	killed := 0
	for _, e := range entries {
		// Skip orchestrator unless --all
		if !*all && orchName != "" && e.WorkerID == orchName {
			continue
		}

		// Verify PID belongs to us
		if !process.IsOurProcess(e.PID, e.StartTimeNs) {
			fmt.Fprintf(os.Stderr, "  warning: %s PID %d no longer our process, cleaning registry only\n", e.WorkerID, e.PID)
		} else {
			terminated := true
			if e.Mode == "tmux" && e.Pane != "" {
				// tmux workers: kill pane only, don't kill process group
				if err := process.TerminateTmux(e.Pane); err != nil {
					fmt.Fprintf(os.Stderr, "  warning: tmux kill-pane %s: %v\n", e.WorkerID, err)
					terminated = false
				}
			} else {
				// bg workers: kill process + process group
				if err := process.Terminate(e.PID); err != nil {
					fmt.Fprintf(os.Stderr, "  warning: terminate %s pid %d: %v\n", e.WorkerID, e.PID, err)
					terminated = false
				}
			}
			if !terminated {
				fmt.Fprintf(os.Stderr, "  warning: skipping cleanup for %s — termination failed\n", e.WorkerID)
				continue
			}
		}

		// Clear assignee and clean up
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := client.ClearAssignee(ctx, e.WorkerID); err != nil {
			fmt.Fprintf(os.Stderr, "  warning: clear assignee %s: %v\n", e.WorkerID, err)
		}
		if err := reg.Delete(e.WorkerID); err != nil {
			fmt.Fprintf(os.Stderr, "  warning: registry delete %s: %v\n", e.WorkerID, err)
		}
		fmt.Printf("  Killed %s (pid=%d)\n", e.WorkerID, e.PID)
		killed++
	}
	fmt.Printf("Stopped %d workers\n", killed)
	return nil
}
