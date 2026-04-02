package cmd

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"boring-swarm/cli/bsw/beads"
	"boring-swarm/cli/bsw/config"
	"boring-swarm/cli/bsw/monitor"
	"boring-swarm/cli/bsw/persona"
	"boring-swarm/cli/bsw/process"
)

func runDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	project := fs.String("project", ".", "project root directory")
	fix := fs.Bool("fix", false, "auto-fix issues (runs gc, cleans stale entries)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	root, err := projectRootFromFlag(*project)
	if err != nil {
		return err
	}

	issues := 0
	ok := func(msg string) { fmt.Printf("  ok  %s\n", msg) }
	warn := func(msg string) { issues++; fmt.Printf("  !!  %s\n", msg) }

	fmt.Println("bsw doctor")
	fmt.Println()

	// 1. Check tools
	fmt.Println("[tools]")
	for _, bin := range []string{"br", "tmux"} {
		if _, err := exec.LookPath(bin); err != nil {
			warn(fmt.Sprintf("%s not found in PATH", bin))
		} else {
			ok(fmt.Sprintf("%s found", bin))
		}
	}
	// Check at least one provider
	foundProvider := false
	for _, bin := range []string{"claude", "codex"} {
		if _, err := exec.LookPath(bin); err == nil {
			ok(fmt.Sprintf("%s found", bin))
			foundProvider = true
		}
	}
	if !foundProvider {
		warn("no provider CLI found (need claude or codex)")
	}

	// 2. Check personas
	fmt.Println("\n[personas]")
	personas, err := persona.LoadDir(root + "/personas")
	if err != nil {
		warn(fmt.Sprintf("cannot load personas: %v — run: bsw init", err))
	} else if len(personas) == 0 {
		warn("no personas found — run: bsw init")
	} else {
		for name, p := range personas {
			promptPath := root + "/" + p.Prompt
			if _, err := os.Stat(promptPath); err != nil {
				warn(fmt.Sprintf("persona %q: prompt file missing: %s", name, p.Prompt))
			} else {
				ok(fmt.Sprintf("persona %q (provider=%s, model=%s)", name, p.Provider, p.Model))
			}
		}
	}

	// 3. Check worker registry
	fmt.Println("\n[workers]")
	reg := process.NewRegistry(root)
	entries, err := reg.LoadAll()
	if err != nil {
		warn(fmt.Sprintf("cannot load registry: %v", err))
	} else if len(entries) == 0 {
		ok("no workers registered")
	} else {
		dead := 0
		orphans := 0
		stale := 0
		running := 0
		for _, e := range entries {
			s := monitor.CheckWorker(e, config.StaleTimeout())
			switch s.State {
			case monitor.Running:
				running++
			case monitor.Stale:
				stale++
				warn(fmt.Sprintf("worker %s is stale (no activity for %s)", e.WorkerID, s.LastActivity))
			case monitor.Orphan:
				orphans++
				warn(fmt.Sprintf("worker %s is orphaned (pane gone, pid %d still alive)", e.WorkerID, e.PID))
			default:
				dead++
				warn(fmt.Sprintf("worker %s is dead (state=%s, pid=%d)", e.WorkerID, s.State, e.PID))
			}
		}
		if running > 0 {
			ok(fmt.Sprintf("%d workers running", running))
		}
		if dead > 0 || orphans > 0 {
			if *fix {
				fmt.Println("\n  fixing: running gc...")
				_ = runGC([]string{"--project", *project})
			} else {
				warn(fmt.Sprintf("%d dead + %d orphaned workers (run with --fix or bsw gc)", dead, orphans))
			}
		}
	}

	// 4. Check beads access
	fmt.Println("\n[beads]")
	ctx, cancel := context.WithTimeout(context.Background(), config.DoctorTimeout())
	defer cancel()
	client := beads.Client{Workdir: root}
	allIssues, err := client.List(ctx, 0)
	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "executable file not found") {
			warn("br CLI not available")
		} else {
			warn(fmt.Sprintf("br list failed: %v", err))
		}
	} else {
		open := 0
		for _, i := range allIssues {
			if strings.EqualFold(i.Status, "open") {
				open++
			}
		}
		ok(fmt.Sprintf("br accessible (%d beads, %d open)", len(allIssues), open))
	}

	// 5. Check agent-mail
	fmt.Println("\n[agent-mail]")
	amCfg := process.DefaultAgentMailConfig()
	if amCfg.Token == "" {
		warn("agent-mail token not configured (set AGENT_MAIL_TOKEN or store in vault at secret/agent/mail)")
	} else {
		ok("agent-mail token configured")
		// Health check the server
		if err := amCfg.HealthCheck(); err != nil {
			warn(fmt.Sprintf("agent-mail server unreachable: %v", err))
		} else {
			ok(fmt.Sprintf("agent-mail server ok (%s)", amCfg.URL))
		}
	}
	hookPath := process.InboxCheckHookPath()
	if hookPath != "" {
		ok(fmt.Sprintf("inbox nudge hook found (%s)", hookPath))
	} else {
		warn("inbox nudge hook not found (check_inbox.sh)")
	}

	// 6. Check tmux
	fmt.Println("\n[tmux]")
	if out, err := exec.Command("tmux", "list-sessions").Output(); err != nil {
		ok("no tmux sessions active")
	} else {
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		bswSessions := 0
		for _, l := range lines {
			if strings.HasPrefix(l, "bsw-") {
				bswSessions++
			}
		}
		ok(fmt.Sprintf("%d tmux sessions (%d bsw-*)", len(lines), bswSessions))
	}

	// Summary
	fmt.Println()
	if issues == 0 {
		fmt.Println("All checks passed.")
	} else {
		fmt.Printf("%d issue(s) found.\n", issues)
	}
	return nil
}
