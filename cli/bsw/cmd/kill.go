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

func runKill(args []string) error {
	fs := flag.NewFlagSet("kill", flag.ContinueOnError)
	project := fs.String("project", ".", "project root directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return fmt.Errorf("usage: bsw kill <bead-id>")
	}
	beadID := fs.Arg(0)
	root, err := projectRootFromFlag(*project)
	if err != nil {
		return err
	}

	reg := process.NewRegistry(root)
	entry, err := reg.Load(beadID)
	if err != nil {
		return fmt.Errorf("worker %s not found in registry", beadID)
	}

	// Verify PID belongs to us before killing
	if !process.IsOurProcess(entry.PID, entry.StartTimeNs) {
		fmt.Fprintf(os.Stderr, "  warning: PID %d is no longer our process (reused), skipping termination\n", entry.PID)
	} else {
		terminated := true
		if entry.Mode == "tmux" && entry.Pane != "" {
			// For tmux workers: kill the pane only. Don't kill the process group
			// because it may share the tmux server's group and nuke the orchestrator.
			if err := process.TerminateTmux(entry.Pane); err != nil {
				fmt.Fprintf(os.Stderr, "  warning: tmux kill-pane: %v\n", err)
				terminated = false
			}
		} else {
			// For bg workers: kill process + process group
			if err := process.Terminate(entry.PID); err != nil {
				fmt.Fprintf(os.Stderr, "  warning: terminate pid %d: %v\n", entry.PID, err)
				terminated = false
			}
		}
		if !terminated {
			return fmt.Errorf("failed to terminate worker %s (pid=%d) — not cleaning up", beadID, entry.PID)
		}
	}

	// Only unclaim and delete registry after successful termination
	var errs []string
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client := beads.Client{Workdir: root}
	if err := client.ClearAssignee(ctx, beadID); err != nil {
		errs = append(errs, fmt.Sprintf("unclaim: %v", err))
	}

	if err := reg.Delete(beadID); err != nil {
		errs = append(errs, fmt.Sprintf("registry delete: %v", err))
	}

	fmt.Printf("Killed worker on %s (pid=%d)\n", beadID, entry.PID)
	for _, e := range errs {
		fmt.Fprintf(os.Stderr, "  warning: %s\n", e)
	}
	return nil
}
