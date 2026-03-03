package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"path/filepath"

	"boring-swarm/cli/bsw/beads"
	"boring-swarm/cli/bsw/dsl"
	"boring-swarm/cli/bsw/status"
)

func runStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	project := fs.String("project", ".", "project root")
	jsonOut := fs.Bool("json", false, "emit json snapshot")
	explain := fs.Bool("explain", false, "include deterministic reason fields")
	flowPath := fs.String("flow", "", "flow path override")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	root, err := projectRootFromFlag(*project)
	if err != nil {
		return err
	}

	resolvedFlow := *flowPath
	if resolvedFlow == "" {
		rs, err := loadRunStateSafe(root)
		if err == nil {
			resolvedFlow = rs.Flow
		}
	}
	var spec *dsl.FlowSpec
	if resolvedFlow != "" {
		if !filepath.IsAbs(resolvedFlow) {
			resolvedFlow = filepath.Join(root, resolvedFlow)
		}
		spec, _ = dsl.ParseFile(resolvedFlow)
	}

	snap, err := status.BuildSnapshot(context.Background(), root, beads.Client{Workdir: root}, spec, *explain)
	if err != nil {
		return err
	}

	if *jsonOut {
		enc := json.NewEncoder(stdoutWriter{})
		enc.SetIndent("", "  ")
		return enc.Encode(snap)
	}

	fmt.Printf("run=%s mode=%s status=%s\n", snap.Run.RunID, snap.Run.Mode, snap.Run.Status)
	for q, st := range snap.Queues {
		fmt.Printf("queue %s: total=%d unassigned=%d assigned=%d\n", q, st.Total, st.Unassigned, st.Assigned)
	}
	fmt.Printf("beads=%d agents=%d attention=%d\n", len(snap.Beads), len(snap.Agents), len(snap.Attention))
	return nil
}

type stdoutWriter struct{}

func (stdoutWriter) Write(p []byte) (int, error) {
	return fmt.Print(string(p))
}
