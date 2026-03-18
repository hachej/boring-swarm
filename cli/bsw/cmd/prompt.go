package cmd

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"boring-swarm/cli/bsw/persona"
)

// Default search path for the shared prompt library.
// Override with BSW_PROMPT_LIB env var.
const defaultPromptLib = "/home/ubuntu/projects/boring-coding/prompts"

func runPrompt(args []string) error {
	fs := flag.NewFlagSet("prompt", flag.ContinueOnError)
	project := fs.String("project", ".", "project root directory")
	list := fs.Bool("list", false, "list all available prompts")
	if err := fs.Parse(args); err != nil {
		return err
	}

	root, err := projectRootFromFlag(*project)
	if err != nil {
		return err
	}

	libDir := promptLibDir()

	if *list {
		return listPrompts(root, libDir)
	}

	if fs.NArg() == 0 {
		return fmt.Errorf("usage: bsw prompt <name>           (persona: worker, reviewer)\n" +
			"       bsw prompt <category/name>   (library: review/fresh_eyes, research/go_deeper)\n" +
			"       bsw prompt --list             (show all available prompts)")
	}
	name := fs.Arg(0)

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
			// Show which one we resolved to
			rel, _ := filepath.Rel(libDir, match)
			fmt.Fprintf(os.Stderr, "bsw prompt: resolved to %s\n", rel)
			fmt.Print(string(data))
			return nil
		}
	}

	return fmt.Errorf("prompt %q not found (checked personas/ and %s)", name, libDir)
}

func promptLibDir() string {
	if v := os.Getenv("BSW_PROMPT_LIB"); v != "" {
		return v
	}
	return defaultPromptLib
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
		fmt.Fprintf(os.Stderr, "Library not found at %s (set BSW_PROMPT_LIB to override)\n", libDir)
	}

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
