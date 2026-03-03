package cmd

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"time"

	"boring-swarm/v2/cli/bsw/beads"
)

func runPing(args []string) error {
	flagArgs, beadArg, extras := splitArgs(args, map[string]bool{
		"project": true,
		"actor":   true,
	})
	fs := flag.NewFlagSet("ping", flag.ContinueOnError)
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
		return fmt.Errorf("ping requires <bead-id>")
	}
	root, err := projectRootFromFlag(*project)
	if err != nil {
		return err
	}
	beadID := beadArg
	client := beads.Client{Workdir: root, Actor: *actor}
	msg := fmt.Sprintf("PING from bsw at %s: check agent-mail and continue this assignment.", time.Now().UTC().Format(time.RFC3339))
	if err := client.AddComment(context.Background(), beadID, msg); err != nil {
		return err
	}
	fmt.Printf("ping sent to %s\n", beadID)
	return nil
}
