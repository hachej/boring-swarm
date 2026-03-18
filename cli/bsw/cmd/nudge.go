package cmd

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"boring-swarm/cli/bsw/process"
)

func runNudge(args []string) error {
	fs := flag.NewFlagSet("nudge", flag.ContinueOnError)
	project := fs.String("project", ".", "project root directory")
	msg := fs.String("msg", "Keep working. Check your inbox for new messages.", "message to send")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return fmt.Errorf("usage: bsw nudge <worker-id>")
	}
	workerID := fs.Arg(0)
	root, err := projectRootFromFlag(*project)
	if err != nil {
		return err
	}

	// Always clear the rate-limit file so the next hook check is immediate
	clearNudgeRateLimit(workerID)

	reg := process.NewRegistry(root)
	entry, err := reg.Load(workerID)
	if err != nil {
		// Not in registry — still cleared rate-limit, that's enough
		fmt.Printf("Nudged %s (cleared rate-limit)\n", workerID)
		return nil
	}

	if entry.Mode == "tmux" && entry.Pane != "" {
		// Clear any partial input on the line, then type message + Enter
		// C-u clears the line (do NOT send C-c — it kills the agent process)
		clearCmd := exec.Command("tmux", "send-keys", "-t", entry.Pane, "C-u")
		_ = clearCmd.Run() // best-effort

		sendCmd := exec.Command("tmux", "send-keys", "-t", entry.Pane, *msg, "Enter")
		if err := sendCmd.Run(); err != nil {
			return fmt.Errorf("tmux send-keys failed: %w", err)
		}
		fmt.Printf("Nudged worker %s (tmux pane %s + cleared rate-limit)\n", workerID, entry.Pane)
	} else {
		fmt.Printf("Nudged worker %s (cleared rate-limit)\n", workerID)
	}
	return nil
}

// clearNudgeRateLimit removes the rate-limit file for check_inbox.sh
// so the next hook invocation checks the inbox immediately.
func clearNudgeRateLimit(agentName string) {
	// Match the rate-limit file naming from check_inbox.sh:
	// RATE_FILE="/tmp/mcp-mail-check-${AGENT//[^a-zA-Z0-9]/_}"
	safe := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			return r
		}
		return '_'
	}, agentName)
	os.Remove("/tmp/mcp-mail-check-" + safe)
}
