package cmd

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"boring-swarm/cli/bsw/beads"
	"boring-swarm/cli/bsw/engine"
	"boring-swarm/cli/bsw/process"
)

func runStop(args []string) error {
	fs := flag.NewFlagSet("stop", flag.ContinueOnError)
	project := fs.String("project", ".", "project root")
	actor := fs.String("actor", defaultActor, "actor")
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

	signalPath := filepath.Join(root, ".bsw", "stop.signal")
	_ = os.MkdirAll(filepath.Dir(signalPath), 0o755)
	_ = os.WriteFile(signalPath, []byte(time.Now().UTC().Format(time.RFC3339)), 0o644)

	reg := process.NewRegistry(root)
	runtimes, _ := reg.LoadAll()
	client := beads.Client{Workdir: root, Actor: *actor}
	for _, rt := range runtimes {
		_ = process.Terminate(rt.PID)
		_ = client.ClearAssigneeIfMatch(context.Background(), rt.BeadID, rt.AgentName, *actor)
		_ = reg.Delete(rt.BeadID)
	}

	serviceKilled := 0
	services, _ := engine.ListServiceProcesses(root)
	for _, sp := range services {
		if process.IsAlive(sp.PID) {
			_ = process.Terminate(sp.PID)
			serviceKilled++
		}
	}
	// Best-effort cleanup of service registry artifacts (live or stale).
	for _, sp := range services {
		_ = os.Remove(sp.Path)
	}

	rs, _ := engine.LoadRunState(root)
	if rs.RunID == "" {
		rs.RunID = engine.NewRunID()
	}
	if rs.PID > 0 && process.IsAlive(rs.PID) {
		_ = process.Terminate(rs.PID)
		serviceKilled++
	}
	rs.Status = "stopped"
	if rs.StartedAt == "" {
		rs.StartedAt = time.Now().UTC().Format(time.RFC3339)
	}
	rs.PID = 0
	_ = engine.SaveRunState(root, rs)
	fmt.Printf("stop requested; terminated %d worker(s), %d service process(es)\n", len(runtimes), serviceKilled)
	return nil
}
