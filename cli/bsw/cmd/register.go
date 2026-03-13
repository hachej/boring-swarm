package cmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"boring-swarm/cli/bsw/process"

	"gopkg.in/yaml.v3"
)

func runRegister(args []string) error {
	fs := flag.NewFlagSet("register", flag.ContinueOnError)
	project := fs.String("project", ".", "project root directory")
	personaName := fs.String("persona", "orchestrator", "persona name for registration")
	bridgeConfig := fs.String("bridge-config", defaultBridgeConfig(), "bridge config.yaml path")
	channel := fs.String("channel", "", "Slack channel name (default: auto from project name)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	root, err := projectRootFromFlag(*project)
	if err != nil {
		return err
	}
	absRoot, _ := filepath.Abs(root)

	// Register with Agent Mail
	amCfg := process.DefaultAgentMailConfig()
	if amCfg.Token == "" {
		return fmt.Errorf("agent-mail not configured (set AGENT_MAIL_TOKEN or store in vault at secret/agent/mail)")
	}

	taskDesc := fmt.Sprintf("%s orchestrator", *personaName)
	reg, err := amCfg.RegisterWorker(absRoot, "claude", "claude-opus-4-6", taskDesc)
	if err != nil {
		return fmt.Errorf("agent-mail registration failed: %w", err)
	}
	fmt.Printf("  agent-mail: registered as %s\n", reg.Name)

	// Write orchestrator file
	orchFile := filepath.Join(root, ".bsw", "orchestrator.json")
	if err := os.MkdirAll(filepath.Dir(orchFile), 0o755); err != nil {
		return fmt.Errorf("create .bsw dir: %w", err)
	}
	orchData, err := json.MarshalIndent(map[string]string{
		"name":    reg.Name,
		"project": absRoot,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal orchestrator data: %w", err)
	}
	if err := os.WriteFile(orchFile, orchData, 0o644); err != nil {
		return fmt.Errorf("write orchestrator file: %w", err)
	}

	// Update bridge config
	if *bridgeConfig != "" {
		slackChannel := *channel
		if slackChannel == "" {
			slackChannel = deriveChannelName(absRoot)
		}

		updated, created, err := updateBridgeConfig(*bridgeConfig, absRoot, reg.Name, slackChannel)
		if err != nil {
			fmt.Printf("  warn: bridge config update failed: %v\n", err)
		} else if created {
			fmt.Printf("  bridge: added project %s -> #%s (orchestrator=%s)\n", absRoot, slackChannel, reg.Name)
		} else if updated {
			fmt.Printf("  bridge: updated orchestrator -> %s\n", reg.Name)
		}

		// Signal bridge to reload (SIGHUP)
		signalBridge()
	}

	// Announce in Slack via operator
	operator := process.OperatorName()
	subject := fmt.Sprintf("%s is online (orchestrator)", reg.Name)
	body := fmt.Sprintf("**%s** registered as orchestrator for `%s`.\n\nSlack messages in this channel will be forwarded to me.",
		reg.Name, filepath.Base(absRoot))
	if err := amCfg.SendMessage(absRoot, reg.Name, operator, subject, body); err != nil {
		fmt.Printf("  warn: announcement failed: %v\n", err)
	}

	fmt.Printf("\nRegistered orchestrator: %s\n", reg.Name)
	fmt.Println("\nExport these in your session:")
	fmt.Printf("  export AGENT_MAIL_PROJECT='%s'\n", absRoot)
	fmt.Printf("  export AGENT_MAIL_AGENT='%s'\n", reg.Name)
	fmt.Printf("  export AGENT_MAIL_URL='%s'\n", amCfg.URL)
	fmt.Printf("  export AGENT_MAIL_TOKEN='%s'\n", amCfg.Token)
	fmt.Printf("  export AGENT_MAIL_INTERVAL=120\n")
	fmt.Printf("  export AGENT_MAIL_OPERATOR='%s'\n", operator)

	return nil
}

// deriveChannelName creates a Slack channel name from a project path.
// /home/ubuntu/projects/boring-swarm → bsw-boring-swarm
func deriveChannelName(absPath string) string {
	base := filepath.Base(absPath)
	// Normalize: lowercase, replace special chars
	name := strings.ToLower(base)
	name = strings.ReplaceAll(name, "_", "-")
	name = strings.ReplaceAll(name, " ", "-")
	return "bsw-" + name
}

// defaultBridgeConfig returns the bridge config path from env or default location.
func defaultBridgeConfig() string {
	if v := os.Getenv("BSW_BRIDGE_CONFIG"); v != "" {
		return v
	}
	// Check common locations
	candidates := []string{
		filepath.Join(os.Getenv("HOME"), "projects/openclaw/config.yaml"),
		filepath.Join(os.Getenv("HOME"), ".bsw-bridge.yaml"),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

// updateBridgeConfig updates or adds a project in the bridge config.yaml.
// Returns (updated, created, error).
func updateBridgeConfig(configPath, projectKey, orchestrator, channel string) (bool, bool, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return false, false, err
	}

	var cfg map[string]any
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return false, false, err
	}

	projects, _ := cfg["projects"].([]any)

	// Find existing project
	for _, p := range projects {
		proj, ok := p.(map[string]any)
		if !ok {
			continue
		}
		if proj["project_key"] == projectKey {
			proj["orchestrator"] = orchestrator
			out, err := yaml.Marshal(cfg)
			if err != nil {
				return false, false, err
			}
			return true, false, os.WriteFile(configPath, out, 0o644)
		}
	}

	// Not found — add new project
	newProj := map[string]any{
		"project_key":   projectKey,
		"slack_channel": "#" + channel,
		"orchestrator":  orchestrator,
	}
	projects = append(projects, newProj)
	cfg["projects"] = projects

	out, err := yaml.Marshal(cfg)
	if err != nil {
		return false, false, err
	}
	return false, true, os.WriteFile(configPath, out, 0o644)
}

// signalBridge sends SIGHUP to the running bridge process.
func signalBridge() {
	// Find bridge PID from common locations
	candidates := []string{
		filepath.Join(os.Getenv("HOME"), "projects/openclaw/bridge.pid"),
	}

	for _, pidFile := range candidates {
		data, err := os.ReadFile(pidFile)
		if err != nil {
			continue
		}
		var pid int
		if _, err := fmt.Sscanf(strings.TrimSpace(string(data)), "%d", &pid); err == nil && pid > 0 {
			proc, err := os.FindProcess(pid)
			if err == nil {
				proc.Signal(os.Signal(signalHUP()))
				fmt.Printf("  bridge: sent SIGHUP to pid %d\n", pid)
				return
			}
		}
	}

	// Try finding bridge by process name
	// Use pgrep as fallback
	if out, err := findBridgePID(); err == nil && out > 0 {
		proc, _ := os.FindProcess(out)
		if proc != nil {
			proc.Signal(os.Signal(signalHUP()))
			fmt.Printf("  bridge: sent SIGHUP to pid %d\n", out)
			return
		}
	}

	fmt.Println("  bridge: could not find running bridge (will auto-reload in ~60s)")
}
