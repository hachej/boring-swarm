package cmd

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"boring-swarm/cli/bsw/beads"
	"boring-swarm/cli/bsw/monitor"
	"boring-swarm/cli/bsw/process"
)

func runGC(args []string) error {
	fs := flag.NewFlagSet("gc", flag.ContinueOnError)
	dryRun := fs.Bool("dry-run", false, "show what would be cleaned without doing it")
	project := fs.String("project", ".", "project root directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	root, err := projectRootFromFlag(*project)
	if err != nil {
		return err
	}

	reg := process.NewRegistry(root)
	entries, err := reg.LoadAll()
	if err != nil {
		return err
	}

	client := beads.Client{Workdir: root}
	cleaned := 0
	for _, e := range entries {
		me := monitor.WorkerEntry{
			WorkerID: e.WorkerID, Persona: e.Persona,
			Mode: e.Mode, PID: e.PID, Pane: e.Pane,
			StartedAt: e.StartedAt, StartTimeNs: e.StartTimeNs, Log: e.Log,
		}
		s := monitor.CheckWorker(me, 0)
		if s.State == monitor.Running || s.State == monitor.Stale {
			continue // still alive
		}

		// For orphans (pane gone but PID alive), verify PID ownership then terminate
		if s.State == monitor.Orphan {
			if *dryRun {
				fmt.Printf("  [dry-run] would terminate orphan %s (pid=%d) and clean\n", e.WorkerID, e.PID)
			} else {
				if process.IsOurProcess(e.PID, e.StartTimeNs) {
					if err := process.Terminate(e.PID); err != nil {
						fmt.Fprintf(os.Stderr, "  warning: terminate orphan %s: %v\n", e.WorkerID, err)
						continue // don't clean up if we can't terminate
					}
				} else {
					fmt.Fprintf(os.Stderr, "  warning: orphan %s PID %d was reused, skipping termination\n", e.WorkerID, e.PID)
				}
			}
		}

		if *dryRun {
			fmt.Printf("  [dry-run] would clean %s (state=%s, pid=%d)\n", e.WorkerID, s.State, e.PID)
		} else {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if err := client.ClearAssignee(ctx, e.WorkerID); err != nil {
				fmt.Fprintf(os.Stderr, "  warning: clear assignee %s: %v\n", e.WorkerID, err)
			}
			cancel()
			if err := reg.Delete(e.WorkerID); err != nil {
				fmt.Fprintf(os.Stderr, "  warning: registry delete %s: %v\n", e.WorkerID, err)
			}
			fmt.Printf("  Cleaned %s (state=%s, pid=%d)\n", e.WorkerID, s.State, e.PID)
		}
		cleaned++
	}

	if cleaned == 0 {
		fmt.Println("Nothing to clean")
	} else if *dryRun {
		fmt.Printf("Would clean %d workers\n", cleaned)
	} else {
		fmt.Printf("Cleaned %d workers\n", cleaned)
	}
	return nil
}
