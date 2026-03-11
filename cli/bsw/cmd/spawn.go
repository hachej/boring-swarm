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
	workerID := fs.String("id", "", "worker ID (default: <persona>-<timestamp>)")
	mode := fs.String("mode", "bg", "spawn mode: bg or tmux")
	session := fs.String("session", currentTmuxSession(), "tmux session for new window (default: current session, use 'new' for separate session)")
	project := fs.String("project", ".", "project root directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// Generate worker ID if not provided
	if *workerID == "" {
		*workerID = fmt.Sprintf("worker-%d", time.Now().Unix())
	}
	if err := process.ValidateBeadID(*workerID); err != nil {
		return err
	}

	root, err := projectRootFromFlag(*project)
	if err != nil {
		return err
	}

	// Check for duplicate
	reg := process.NewRegistry(root)
	if reg.IsActive(*workerID) {
		return fmt.Errorf("worker %s is already running (kill it first with: bsw kill %s)", *workerID, *workerID)
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

	// Read system prompt
	promptPath := filepath.Join(root, p.Prompt)
	promptBytes, err := os.ReadFile(promptPath)
	if err != nil {
		return fmt.Errorf("read prompt %s: %w", promptPath, err)
	}

	// Agent picks its own work — just tell it to start
	userPrompt := "Start working. Follow your system prompt instructions."

	mgr := process.NewManager(root)
	entry, err := mgr.Spawn(process.SpawnSpec{
		BeadID:       *workerID,
		Persona:      *personaName,
		Provider:     p.Provider,
		Model:        p.Model,
		Effort:       p.Effort,
		SystemPrompt: string(promptBytes),
		UserPrompt:   userPrompt,
		ProjectRoot:  root,
		Mode:         *mode,
		TmuxSession:  tmuxSessionValue(*session),
	})
	if err != nil {
		return fmt.Errorf("spawn failed: %w", err)
	}

	if err := reg.Save(entry); err != nil {
		return fmt.Errorf("save registry: %w", err)
	}

	fmt.Printf("Spawned worker %s (pid=%d, mode=%s, yolo)\n", *workerID, entry.PID, entry.Mode)
	if entry.Pane != "" {
		fmt.Printf("  tmux pane: %s (attach with: bsw attach %s)\n", entry.Pane, *workerID)
	}
	fmt.Printf("  log: %s\n", entry.Log)
	return nil
}
