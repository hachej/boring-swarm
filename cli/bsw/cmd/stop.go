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
	if len(entries) == 0 {
		fmt.Println("No active workers")
		return nil
	}

	client := beads.Client{Workdir: root}
	killed := 0
	for _, e := range entries {
		// Verify PID belongs to us
		if !process.IsOurProcess(e.PID, e.StartTimeNs) {
			fmt.Fprintf(os.Stderr, "  warning: %s PID %d no longer our process, cleaning registry only\n", e.BeadID, e.PID)
		} else {
			terminated := true
			if e.Mode == "tmux" && e.Pane != "" {
				// tmux workers: kill pane only, don't kill process group
				if err := process.TerminateTmux(e.Pane); err != nil {
					fmt.Fprintf(os.Stderr, "  warning: tmux kill-pane %s: %v\n", e.BeadID, err)
					terminated = false
				}
			} else {
				// bg workers: kill process + process group
				if err := process.Terminate(e.PID); err != nil {
					fmt.Fprintf(os.Stderr, "  warning: terminate %s pid %d: %v\n", e.BeadID, e.PID, err)
					terminated = false
				}
			}
			if !terminated {
				fmt.Fprintf(os.Stderr, "  warning: skipping cleanup for %s — termination failed\n", e.BeadID)
				continue
			}
		}

		// Unclaim and clean up
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := client.ClearAssignee(ctx, e.BeadID); err != nil {
			fmt.Fprintf(os.Stderr, "  warning: unclaim %s: %v\n", e.BeadID, err)
		}
		cancel()
		if err := reg.Delete(e.BeadID); err != nil {
			fmt.Fprintf(os.Stderr, "  warning: registry delete %s: %v\n", e.BeadID, err)
		}
		fmt.Printf("  Killed %s (pid=%d)\n", e.BeadID, e.PID)
		killed++
	}
	fmt.Printf("Stopped %d workers\n", killed)
	return nil
}
