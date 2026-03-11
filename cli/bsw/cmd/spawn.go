package cmd

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"boring-swarm/cli/bsw/persona"
	"boring-swarm/cli/bsw/process"
)

func runSpawn(args []string) error {
	fs := flag.NewFlagSet("spawn", flag.ContinueOnError)
	personaName := fs.String("persona", "worker", "persona name (matches personas/<name>.toml)")
	workerID := fs.String("id", "", "worker ID (default: agent-mail name or worker-<ts>)")
	mode := fs.String("mode", "bg", "spawn mode: bg or tmux")
	session := fs.String("session", currentTmuxSession(), "tmux session for new window (default: current session, use 'new' for separate session)")
	project := fs.String("project", ".", "project root directory")
	if err := fs.Parse(args); err != nil {
		return err
	}

	root, err := projectRootFromFlag(*project)
	if err != nil {
		return err
	}

	// Auto-init if personas/ doesn't exist
	personaPath := filepath.Join(root, "personas", *personaName+".toml")
	if _, err := os.Stat(personaPath); os.IsNotExist(err) {
		fmt.Println("Personas not found, running bsw init...")
		if initErr := runInit([]string{"--project", root}); initErr != nil {
			return fmt.Errorf("auto-init failed: %w", initErr)
		}
	}

	// Load persona
	p, err := persona.Load(personaPath)
	if err != nil {
		return fmt.Errorf("load persona %q: %w", *personaName, err)
	}

	// Register worker with Agent Mail (before ID generation so we can use the name)
	amCfg := process.DefaultAgentMailConfig()
	var amReg *process.AgentMailRegistration
	var amEnv []string
	if amCfg.Token != "" {
		absRoot, _ := filepath.Abs(root)
		taskDesc := fmt.Sprintf("%s worker", *personaName)
		amModel := p.Model
		if amModel == "" {
			amModel = p.Provider
		}
		reg, err := amCfg.RegisterWorker(absRoot, p.Provider, amModel, taskDesc)
		if err != nil {
			fmt.Printf("  warn: agent-mail registration failed: %v\n", err)
		} else {
			amReg = reg
			amEnv = process.AgentMailEnv(absRoot, reg.Name, amCfg)
			fmt.Printf("  agent-mail: registered as %s\n", reg.Name)
		}
	}

	// Generate worker ID: use agent-mail name if available, else timestamp
	if *workerID == "" {
		if amReg != nil {
			*workerID = amReg.Name
		} else {
			*workerID = fmt.Sprintf("worker-%d", time.Now().UnixMilli()%1000000)
		}
	}
	if err := process.ValidateBeadID(*workerID); err != nil {
		return err
	}

	// Check for duplicate
	reg := process.NewRegistry(root)
	if reg.IsActive(*workerID) {
		return fmt.Errorf("worker %s is already running (kill it first with: bsw kill %s)", *workerID, *workerID)
	}

	// Read system prompt
	promptPath := filepath.Join(root, p.Prompt)
	promptBytes, err := os.ReadFile(promptPath)
	if err != nil {
		return fmt.Errorf("read prompt %s: %w", promptPath, err)
	}

	// Inject the agent's own name into the system prompt so it knows its identity
	systemPrompt := string(promptBytes)
	if amReg != nil {
		systemPrompt = fmt.Sprintf("Your agent-mail name is **%s**. Use this as your identity when sending messages.\n\n%s", amReg.Name, systemPrompt)
	}

	// Agent picks its own work — just tell it to start
	userPrompt := "Start working. Follow your system prompt instructions."

	amName := ""
	if amReg != nil {
		amName = amReg.Name
	}

	mgr := process.NewManager(root)
	entry, err := mgr.Spawn(process.SpawnSpec{
		BeadID:        *workerID,
		Persona:       *personaName,
		Provider:      p.Provider,
		Model:         p.Model,
		Effort:        p.Effort,
		SystemPrompt:  systemPrompt,
		UserPrompt:    userPrompt,
		ProjectRoot:   root,
		Mode:          *mode,
		TmuxSession:   tmuxSessionValue(*session),
		AgentMailEnv:  amEnv,
		AgentMailName: amName,
	})
	if err != nil {
		return fmt.Errorf("spawn failed: %w", err)
	}

	if amReg != nil {
		entry.AgentMailName = amReg.Name
	}

	if err := reg.Save(entry); err != nil {
		return fmt.Errorf("save registry: %w", err)
	}

	// Announce registration to operator (shows up in Slack via bridge)
	if amReg != nil {
		absRoot, _ := filepath.Abs(root)
		operator := process.OperatorName()
		subject := fmt.Sprintf("%s is online", amReg.Name)
		body := fmt.Sprintf("**%s** (%s, %s) spawned in `%s` mode — ready to work.",
			amReg.Name, *personaName, p.Provider, *mode)
		if err := amCfg.SendMessage(absRoot, amReg.Name, operator, subject, body); err != nil {
			fmt.Printf("  warn: announcement failed: %v\n", err)
		}
	}

	fmt.Printf("Spawned worker %s (pid=%d, mode=%s, yolo)\n", *workerID, entry.PID, entry.Mode)
	if entry.Pane != "" {
		fmt.Printf("  tmux pane: %s (attach with: bsw attach %s)\n", entry.Pane, *workerID)
	}
	fmt.Printf("  log: %s\n", entry.Log)
	return nil
}
