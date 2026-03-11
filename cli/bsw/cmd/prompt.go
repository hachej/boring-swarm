package cmd

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"boring-swarm/cli/bsw/persona"
)

func runPrompt(args []string) error {
	fs := flag.NewFlagSet("prompt", flag.ContinueOnError)
	project := fs.String("project", ".", "project root directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return fmt.Errorf("usage: bsw prompt <persona-name>")
	}
	name := fs.Arg(0)

	root, err := projectRootFromFlag(*project)
	if err != nil {
		return err
	}

	p, err := persona.Load(filepath.Join(root, "personas", name+".toml"))
	if err != nil {
		return fmt.Errorf("load persona %q: %w", name, err)
	}

	data, err := os.ReadFile(filepath.Join(root, p.Prompt))
	if err != nil {
		return fmt.Errorf("read prompt: %w", err)
	}

	fmt.Print(string(data))
	return nil
}
