package cmd

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"boring-swarm/cli/bsw/process"
)

func runAttach(args []string) error {
	fs := flag.NewFlagSet("attach", flag.ContinueOnError)
	project := fs.String("project", ".", "project root directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return fmt.Errorf("usage: bsw attach <worker-id>")
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
	if entry.Mode != "tmux" || entry.Pane == "" {
		return fmt.Errorf("worker %s is not in tmux mode", workerID)
	}

	// Exec into tmux attach (replaces this process)
	tmux, err := exec.LookPath("tmux")
	if err != nil {
		return fmt.Errorf("tmux not found: %w", err)
	}
	return syscall.Exec(tmux, []string{"tmux", "attach-session", "-t", entry.Pane}, os.Environ())
}
