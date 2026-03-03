package cmd

import (
	"fmt"
)

func Execute(args []string) error {
	if len(args) == 0 {
		printUsage()
		return nil
	}

	switch args[0] {
	case "init":
		return runInit(args[1:])
	case "doctor":
		return runDoctor(args[1:])
	case "run":
		return runQueue(args[1:])
	case "status":
		return runStatus(args[1:])
	case "serve":
		return runServe(args[1:])
	case "ping":
		return runPing(args[1:])
	case "kill":
		return runKill(args[1:])
	case "stop":
		return runStop(args[1:])
	case "help", "-h", "--help":
		printUsage()
		return nil
	default:
		printUsage()
		return fmt.Errorf("unknown command: %s", args[0])
	}
}

func printUsage() {
	fmt.Print(`bsw v2 - queue orchestration primitives

Usage:
  bsw init [--project .]
  bsw doctor <flow.yaml> [--project .]
  bsw run <flow.yaml> [--project .] [--mode oneshot|service] [--actor bsw] [--poll 2s]
  bsw status [--project .] --json [--explain]
  bsw serve [--project .] [--addr 127.0.0.1:8787] [--flow flows/implement_worker_queue.yml]
  bsw ping <bead-id> [--project .] [--actor bsw]
  bsw kill <bead-id> [--project .] [--actor bsw]
  bsw stop [--project .] [--actor bsw]
`)
}
