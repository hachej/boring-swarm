package cmd

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"boring-swarm/cli/bsw/engine"
)

func runQueue(args []string) error {
	flagArgs, flowArg, extras := splitArgs(args, map[string]bool{
		"project": true,
		"mode":    true,
		"actor":   true,
		"poll":    true,
	})
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	project := fs.String("project", ".", "project root")
	mode := fs.String("mode", "oneshot", "run mode: oneshot|service")
	actor := fs.String("actor", defaultActor, "actor name for br mutations")
	poll := fs.Duration("poll", 2*time.Second, "reconcile interval")
	if err := fs.Parse(flagArgs); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if len(extras) > 0 {
		return fmt.Errorf("unexpected extra arguments: %v", extras)
	}
	if flowArg == "" && fs.NArg() > 0 {
		flowArg = fs.Arg(0)
	}
	if flowArg == "" {
		return fmt.Errorf("run requires <flow.yaml>")
	}
	root, err := projectRootFromFlag(*project)
	if err != nil {
		return err
	}

	flowPath := flowArg
	if !filepath.IsAbs(flowPath) {
		flowPath = filepath.Join(root, flowPath)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	return engine.Run(ctx, engine.RunOptions{
		ProjectRoot:  root,
		FlowPath:     flowPath,
		Mode:         *mode,
		Actor:        *actor,
		PollInterval: *poll,
	})
}
