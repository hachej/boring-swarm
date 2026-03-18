package cmd

import "fmt"

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

You are an orchestrator. Spawn workers, monitor them, keep them running.

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
  bsw prompt <name>                 Print a prompt (persona or library)
  bsw prompt <category/name>        Print from shared library (e.g. review/fresh_eyes)
  bsw prompt --list                 List all available prompts
  bsw review [prompt]               Run code review (auto-detects codex/claude/gemini)
  bsw register                      Register as orchestrator (agent-mail + Slack)
  bsw multi-status                  Status across multiple projects

START:
  1. bsw register
  2. bsw spawn -mode tmux
  3. bsw spawn -mode tmux
  4. bsw watch --interval 3m

ORCHESTRATOR LOOP (what bsw watch does + what you add):
  Each cycle: fetch_inbox → bsw status → br list --status open
  Dead worker?   bsw gc, then bsw spawn -mode tmux
  Stale worker?  bsw nudge <id>, then bsw kill + respawn if stuck
  Slack?         Reply via send_message to GoldOwl

  DO NOT STOP until 0 workers AND 0 open beads.
`)
}
