package cmd

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"boring-swarm/cli/bsw/process"
)

func runLogs(args []string) error {
	fs := flag.NewFlagSet("logs", flag.ContinueOnError)
	follow := fs.Bool("follow", false, "follow log output (tail -f)")
	all := fs.Bool("all", false, "show entire log file")
	n := fs.Int("n", 50, "number of lines to show (default 50)")
	project := fs.String("project", ".", "project root directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return fmt.Errorf("usage: bsw logs <worker-id>")
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

	if _, err := os.Stat(entry.Log); err != nil {
		return fmt.Errorf("log file not found: %s", entry.Log)
	}

	if *follow {
		tailBin, err := exec.LookPath("tail")
		if err != nil {
			return err
		}
		return syscall.Exec(tailBin, []string{"tail", "-f", entry.Log}, os.Environ())
	}

	if *all {
		data, err := os.ReadFile(entry.Log)
		if err != nil {
			return err
		}
		os.Stdout.Write(data)
		return nil
	}

	// Default: show last N lines
	cmd := exec.Command("tail", "-n", fmt.Sprintf("%d", *n), entry.Log)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
