package cmd

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"boring-swarm/cli/bsw/persona"
	"boring-swarm/cli/bsw/templates"
)

// promptLibRepo is the git repo for the shared prompt library.
const promptLibRepo = "https://github.com/boringdata/boring-coding.git"

// promptLibCache is where we sparse-checkout the prompts dir.
func promptLibCache() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".bsw", "prompt-lib")
}

func runPrompt(args []string) error {
	fs := flag.NewFlagSet("prompt", flag.ContinueOnError)
	project := fs.String("project", ".", "project root directory")
	list := fs.Bool("list", false, "list all available prompts")
	sync := fs.Bool("sync", false, "pull latest prompts from boring-coding main")
	if err := fs.Parse(args); err != nil {
		return err
	}

	root, err := projectRootFromFlag(*project)
	if err != nil {
		return err
	}

	libDir := resolvePromptLib()

	if *sync {
		return syncPromptLib()
	}

	if *list {
		return listPrompts(root, libDir)
	}

	if fs.NArg() == 0 {
		return fmt.Errorf("usage: bsw prompt <name>           (persona: worker, reviewer, orchestrator)\n" +
			"       bsw prompt <category/name>   (library: review/fresh_eyes, research/go_deeper)\n" +
			"       bsw prompt --list             (show all available prompts)\n" +
			"       bsw prompt --sync             (pull latest from boring-coding main)")
	}
	name := fs.Arg(0)

	// "list" as positional arg (alias for --list)
	if name == "list" {
		return listPrompts(root, libDir)
	}

	// "orchestrator" is special — it's the help text from root.go, not a persona file
	if name == "orchestrator" {
		return printOrchestratorPrompt()
	}

	// Try 1: local persona (e.g. "worker" -> personas/worker.toml)
	if !strings.Contains(name, "/") {
		personaPath := filepath.Join(root, "personas", name+".toml")
		if p, err := persona.Load(personaPath); err == nil {
			data, err := os.ReadFile(filepath.Join(root, p.Prompt))
			if err != nil {
				return fmt.Errorf("read prompt: %w", err)
			}
			fmt.Print(string(data))
			return nil
		}
	}

	// Try 2: shared library (e.g. "review/fresh_eyes" -> prompts/review/fresh_eyes.md)
	libPath := filepath.Join(libDir, name+".md")
	if data, err := os.ReadFile(libPath); err == nil {
		fmt.Print(string(data))
		return nil
	}

	// Try 3: fuzzy match — name without category (e.g. "fresh_eyes" searches all categories)
	if !strings.Contains(name, "/") {
		if match := findInLib(libDir, name); match != "" {
			data, err := os.ReadFile(match)
			if err != nil {
				return fmt.Errorf("read prompt: %w", err)
			}
			rel, _ := filepath.Rel(libDir, match)
			fmt.Fprintf(os.Stderr, "bsw prompt: resolved to %s\n", rel)
			fmt.Print(string(data))
			return nil
		}
	}

	return fmt.Errorf("prompt %q not found (checked personas/ and %s)\nRun 'bsw prompt --sync' to pull latest prompts", name, libDir)
}

// resolvePromptLib returns the prompt library directory.
// Priority: BSW_PROMPT_LIB env > local clone > cached sparse checkout.
func resolvePromptLib() string {
	// Explicit override
	if v := os.Getenv("BSW_PROMPT_LIB"); v != "" {
		return v
	}

	// Local clone (if boring-coding is checked out nearby)
	localPaths := []string{
		filepath.Join(os.Getenv("HOME"), "projects", "boring-coding", "prompts"),
		"/home/ubuntu/projects/boring-coding/prompts",
	}
	for _, p := range localPaths {
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			// Fetch latest in background (non-blocking, best-effort)
			repoDir := filepath.Dir(p)
			go func() {
				_ = exec.Command("git", "-C", repoDir, "fetch", "-q", "origin", "main").Run()
				_ = exec.Command("git", "-C", repoDir, "merge", "--ff-only", "-q", "origin/main").Run()
			}()
			return p
		}
	}

	// Cached sparse checkout
	cache := promptLibCache()
	promptsDir := filepath.Join(cache, "prompts")
	if info, err := os.Stat(promptsDir); err == nil && info.IsDir() {
		// Fetch latest in background
		go func() {
			_ = exec.Command("git", "-C", cache, "fetch", "-q", "origin", "main").Run()
			_ = exec.Command("git", "-C", cache, "merge", "--ff-only", "-q", "origin/main").Run()
		}()
		return promptsDir
	}

	// Not available yet — trigger sync
	fmt.Fprintln(os.Stderr, "bsw prompt: library not cached yet, run 'bsw prompt --sync'")
	return promptsDir
}

// syncPromptLib clones or pulls the prompt library.
func syncPromptLib() error {
	// If local clone exists, fetch and reset main to origin
	localRepo := filepath.Join(os.Getenv("HOME"), "projects", "boring-coding")
	if _, err := os.Stat(filepath.Join(localRepo, "prompts")); err == nil {
		fmt.Fprintf(os.Stderr, "bsw prompt: fetching %s ...\n", localRepo)
		fetch := exec.Command("git", "-C", localRepo, "fetch", "origin", "main")
		fetch.Stderr = os.Stderr
		if err := fetch.Run(); err != nil {
			return fmt.Errorf("git fetch failed: %w", err)
		}
		// Show what changed in prompts/
		diff := exec.Command("git", "-C", localRepo, "diff", "--stat", "HEAD..origin/main", "--", "prompts/")
		diff.Stdout = os.Stderr
		diff.Run()
		// Fast-forward main if on it, otherwise just report
		branch, _ := exec.Command("git", "-C", localRepo, "branch", "--show-current").Output()
		if strings.TrimSpace(string(branch)) == "main" {
			merge := exec.Command("git", "-C", localRepo, "merge", "--ff-only", "origin/main")
			merge.Stdout = os.Stderr
			merge.Stderr = os.Stderr
			merge.Run() // best-effort, may fail if dirty
		}
		fmt.Fprintln(os.Stderr, "bsw prompt: synced")
		return nil
	}

	// Sparse checkout into cache (only prompts/ dir)
	cache := promptLibCache()
	if _, err := os.Stat(filepath.Join(cache, ".git")); err == nil {
		// Already cloned, just pull
		fmt.Fprintf(os.Stderr, "bsw prompt: pulling %s ...\n", cache)
		cmd := exec.Command("git", "-C", cache, "pull", "--ff-only")
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}

	// Fresh sparse clone
	fmt.Fprintf(os.Stderr, "bsw prompt: cloning prompts from %s ...\n", promptLibRepo)

	// Get GitHub token for private repo access
	token := gitHubToken()

	repoURL := promptLibRepo
	if token != "" {
		repoURL = strings.Replace(repoURL, "https://", "https://oauth2:"+token+"@", 1)
	}

	if err := os.MkdirAll(cache, 0o755); err != nil {
		return err
	}

	// Init + sparse checkout for just prompts/
	cmds := [][]string{
		{"git", "init"},
		{"git", "remote", "add", "origin", repoURL},
		{"git", "config", "core.sparseCheckout", "true"},
	}
	for _, c := range cmds {
		cmd := exec.Command(c[0], c[1:]...)
		cmd.Dir = cache
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("%s failed: %w", strings.Join(c, " "), err)
		}
	}

	// Write sparse checkout config
	scDir := filepath.Join(cache, ".git", "info")
	os.MkdirAll(scDir, 0o755)
	os.WriteFile(filepath.Join(scDir, "sparse-checkout"), []byte("prompts/\n"), 0o644)

	// Pull
	cmd := exec.Command("git", "pull", "--depth=1", "origin", "main")
	cmd.Dir = cache
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git pull failed: %w", err)
	}

	fmt.Fprintln(os.Stderr, "bsw prompt: synced")
	return nil
}

// gitHubToken tries to get a GitHub token from vault or env.
func gitHubToken() string {
	if v := os.Getenv("GITHUB_TOKEN"); v != "" {
		return v
	}
	out, err := exec.Command("vault", "kv", "get", "-field=token", "secret/agent/boringdata-agent").Output()
	if err == nil {
		return strings.TrimSpace(string(out))
	}
	return ""
}

func listPrompts(projectRoot, libDir string) error {
	// Local personas
	personaDir := filepath.Join(projectRoot, "personas")
	if entries, err := os.ReadDir(personaDir); err == nil {
		fmt.Println("Personas (local):")
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".toml") {
				name := strings.TrimSuffix(e.Name(), ".toml")
				fmt.Printf("  %s\n", name)
			}
		}
		fmt.Println()
	}

	// Shared library
	if entries, err := os.ReadDir(libDir); err == nil {
		fmt.Println("Library (" + libDir + "):")
		for _, e := range entries {
			if !e.IsDir() || e.Name() == "archive" || e.Name() == "scripts" {
				continue
			}
			category := e.Name()
			subEntries, err := os.ReadDir(filepath.Join(libDir, category))
			if err != nil {
				continue
			}
			var names []string
			for _, se := range subEntries {
				if strings.HasSuffix(se.Name(), ".md") {
					names = append(names, strings.TrimSuffix(se.Name(), ".md"))
				}
			}
			if len(names) > 0 {
				fmt.Printf("  %s/\n", category)
				for _, n := range names {
					fmt.Printf("    %s/%s\n", category, n)
				}
			}
		}
	} else {
		fmt.Fprintf(os.Stderr, "Library not found. Run 'bsw prompt --sync' to fetch.\n")
	}

	return nil
}

func printOrchestratorPrompt() error {
	data, err := templates.Personas.ReadFile("personas/prompts/orchestrator.md")
	if err != nil {
		return fmt.Errorf("read orchestrator prompt: %w", err)
	}
	fmt.Print(string(data))
	return nil
}

// findInLib searches all subdirectories of libDir for name.md
func findInLib(libDir, name string) string {
	entries, err := os.ReadDir(libDir)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if !e.IsDir() || e.Name() == "archive" || e.Name() == "scripts" {
			continue
		}
		candidate := filepath.Join(libDir, e.Name(), name+".md")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return ""
}
