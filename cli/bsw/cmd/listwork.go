package cmd

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"boring-swarm/cli/bsw/beads"
)

func runListWork(args []string) error {
	fs := flag.NewFlagSet("list-work", flag.ContinueOnError)
	label := fs.String("label", "", "bead label to filter by (required)")
	project := fs.String("project", ".", "project root directory")
	asJSON := fs.Bool("json", false, "output as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *label == "" {
		return fmt.Errorf("--label is required")
	}
	root, err := projectRootFromFlag(*project)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	client := beads.Client{Workdir: root}
	issues, err := client.ListByLabel(ctx, *label)
	if err != nil {
		return err
	}

	// Filter to unassigned only
	var available []beads.Issue
	for _, i := range issues {
		if strings.TrimSpace(i.Assignee) == "" {
			available = append(available, i)
		}
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(available)
	}

	if len(available) == 0 {
		fmt.Printf("No unassigned beads with label %q\n", *label)
		return nil
	}
	fmt.Printf("Available beads (%s): %d\n\n", *label, len(available))
	for _, i := range available {
		fmt.Printf("  %s  %s\n", i.ID, i.Title)
	}
	return nil
}
