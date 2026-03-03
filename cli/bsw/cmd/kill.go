package cmd

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"boring-swarm/cli/bsw/beads"
	"boring-swarm/cli/bsw/process"
)

func runKill(args []string) error {
	flagArgs, beadArg, extras := splitArgs(args, map[string]bool{
		"project": true,
		"actor":   true,
	})
	fs := flag.NewFlagSet("kill", flag.ContinueOnError)
	project := fs.String("project", ".", "project root")
	actor := fs.String("actor", defaultActor, "actor")
	if err := fs.Parse(flagArgs); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if len(extras) > 0 {
		return fmt.Errorf("unexpected extra arguments: %v", extras)
	}
	if beadArg == "" && fs.NArg() > 0 {
		beadArg = fs.Arg(0)
	}
	if beadArg == "" {
		return fmt.Errorf("kill requires <bead-id>")
	}
	root, err := projectRootFromFlag(*project)
	if err != nil {
		return err
	}
	beadID := beadArg

	reg := process.NewRegistry(root)
	rt, err := reg.Load(beadID)
	if err != nil {
		return fmt.Errorf("runtime for %s not found", beadID)
	}
	_ = process.Terminate(rt.PID)
	client := beads.Client{Workdir: root, Actor: *actor}
	_ = client.ClearAssigneeIfMatch(context.Background(), beadID, rt.AgentName, *actor)
	_ = reg.Delete(beadID)

	fmt.Printf("killed worker for %s (pid=%d)\n", beadID, rt.PID)
	return nil
}
