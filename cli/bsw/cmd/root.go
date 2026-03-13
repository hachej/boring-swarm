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
  bsw prompt <persona>              Print a persona's system prompt
  bsw register                      Register as orchestrator (agent-mail + Slack)
  bsw multi-status                  Status across multiple projects

Workers are codex/claude agents. They pick their own beads via br robot next.
Just spawn them — don't configure anything.

START:
  1. bsw register              (register as orchestrator, set up Slack)
  2. br list --status open      (check there is work)
  3. bsw spawn                  (spawn workers)
  4. bsw spawn

MONITOR LOOP — after spawning, start a recurring check:

  /loop 30s bsw status --json && br list --status open

  On each cycle:
    - Dead worker?  bsw gc, then bsw spawn.
    - Stale worker? Investigate before killing:
      1. bsw logs <id> — read last output to understand why it stalled.
      2. Check agent-mail inbox for messages from the worker.
      3. bsw nudge <id> — send "continue" to tmux pane.
      4. Only kill if truly stuck: bsw kill <id>, then bsw spawn.

  DO NOT STOP. DO NOT END YOUR SESSION. DO NOT KILL YOUR TMUX SESSION.
  Keep the loop running until status shows 0 workers
  AND br list --status open shows 0 beads.
  Only then: bsw stop (this stops workers, NOT your session)
`)
}
