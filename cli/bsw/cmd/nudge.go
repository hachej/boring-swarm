package cmd

import (
	"flag"
	"fmt"
	"os/exec"

	"boring-swarm/cli/bsw/process"
)

func runNudge(args []string) error {
	fs := flag.NewFlagSet("nudge", flag.ContinueOnError)
	project := fs.String("project", ".", "project root directory")
	msg := fs.String("msg", "You appear stale. Continue working on your current bead.", "message to send")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return fmt.Errorf("usage: bsw nudge <worker-id>")
	}
	workerID := fs.Arg(0)
	root, err := projectRootFromFlag(*project)
	if err != nil {
		return err
	}

	reg := process.NewRegistry(root)
	entry, err := reg.Load(workerID)
	if err != nil {
		return fmt.Errorf("worker %s not found in registry", workerID)
	}

	if entry.Mode == "tmux" && entry.Pane != "" {
		// Send keystrokes to the tmux pane
		cmd := exec.Command("tmux", "send-keys", "-t", entry.Pane, *msg, "Enter")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("tmux send-keys failed: %w", err)
		}
		fmt.Printf("Nudged worker %s (tmux pane %s)\n", workerID, entry.Pane)
	} else {
		fmt.Printf("Worker %s is in bg mode — cannot nudge (kill and respawn instead)\n", workerID)
	}
	return nil
}
