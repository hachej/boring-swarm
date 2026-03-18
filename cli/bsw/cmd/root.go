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

Workers are codex/claude agents. They pick their own beads via br ready --robot --unassigned.
Just spawn them — don't configure anything.

START:
  1. bsw register              (register as orchestrator, set up Slack channel)
  2. br list --status open      (check there is work)
  3. bsw spawn -mode tmux       (spawn workers as tmux panes)
  4. bsw spawn -mode tmux

  Register saves your tmux pane so Slack messages wake you via nudge.
  Workers spawn as split panes in your current tmux session.

MONITOR LOOP — after spawning, start a recurring check:

  /loop 1m fetch_inbox, then bsw status --json && br list --status open

  On each cycle:
    1. CHECK YOUR INBOX first (fetch_inbox). Slack messages and worker
       reports arrive here. Read and act on them before anything else.
    2. Dead worker?  bsw gc, then bsw spawn -mode tmux.
    3. Stale worker? Investigate before killing:
       a. bsw logs <id> — read last output to understand why it stalled.
       b. Check agent-mail inbox for messages from the worker.
       c. bsw nudge <id> — send "continue" to tmux pane.
       d. Only kill if truly stuck: bsw kill <id>, then bsw spawn -mode tmux.

  DO NOT STOP. DO NOT END YOUR SESSION. DO NOT KILL YOUR TMUX SESSION.
  Keep the loop running until status shows 0 workers
  AND br list --status open shows 0 beads.
  Only then: bsw stop (this stops workers, NOT your session)

SLACK:
  Messages in your Slack channel are forwarded to you via Agent Mail.
  The bridge calls "bsw nudge" to wake you when idle.
  Reply via send_message to GoldOwl — it posts back to Slack.
`)
}
