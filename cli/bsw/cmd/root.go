package cmd

import (
	"fmt"

	"boring-swarm/cli/bsw/templates"
)

func Execute(args []string) error {
	if len(args) == 0 {
		printUsage()
		return nil
	}
	switch args[0] {
	case "init":
		return runInit(args[1:])
	case "list-work":
		return runListWork(args[1:])
	case "spawn":
		return runSpawn(args[1:])
	case "status":
		return runStatus(args[1:])
	case "kill":
		return runKill(args[1:])
	case "stop":
		return runStop(args[1:])
	case "attach":
		return runAttach(args[1:])
	case "nudge":
		return runNudge(args[1:])
	case "logs":
		return runLogs(args[1:])
	case "gc":
		return runGC(args[1:])
	case "watch":
		return runWatch(args[1:])
	case "doctor":
		return runDoctor(args[1:])
	case "prompt":
		return runPrompt(args[1:])
	case "register":
		return runRegister(args[1:])
	case "multi-status":
		return runMultiStatus(args[1:])
	case "review":
		return runReview(args[1:])
	case "help", "-h", "--help":
		printUsage()
		return nil
	default:
		printUsage()
		return fmt.Errorf("unknown command: %s", args[0])
	}
}

func printUsage() {
	fmt.Print(`bsw - swarm process manager

Commands:
  bsw init                          Scaffold personas and prompts
  bsw spawn                         Spawn a worker
  bsw status [--json]               Worker health (pid, uptime, activity)
  bsw kill <worker-id>              Kill a worker
  bsw stop                          Stop all workers (NOT your session)
  bsw gc                            Clean up dead workers
  bsw logs <worker-id> [--follow]   View worker output
  bsw nudge <worker-id>             Send "continue" to stale tmux worker
  bsw attach <worker-id>            Attach to tmux worker
  bsw doctor [--fix]                Check setup
  bsw watch [--interval 30s]        Continuous monitor loop
  bsw list-work --label <label>     Show available beads by label
  bsw prompt <name>                 Print a prompt (worker, reviewer, orchestrator)
  bsw prompt list                   List all available prompts
  bsw review [-bead <id>]           Run code review (roborev/claude/gemini/codex)
  bsw register                      Register as orchestrator (agent-mail + Slack)
  bsw multi-status                  Status across multiple projects

`)
	// Print orchestrator prompt from the single source of truth
	data, err := templates.Personas.ReadFile("personas/prompts/orchestrator.md")
	if err == nil {
		fmt.Print(string(data))
	}
}
