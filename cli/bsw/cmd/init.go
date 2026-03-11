package cmd

import (
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"boring-swarm/cli/bsw/templates"
)

func runInit(args []string) error {
	fset := flag.NewFlagSet("init", flag.ContinueOnError)
	project := fset.String("project", ".", "project root directory")
	if err := fset.Parse(args); err != nil {
		return err
	}
	root, err := projectRootFromFlag(*project)
	if err != nil {
		return err
	}

	created := 0
	skipped := 0

	err = fs.WalkDir(templates.Personas, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		dest := filepath.Join(root, path)

		if d.IsDir() {
			return os.MkdirAll(dest, 0o755)
		}

		// Don't overwrite existing files
		if _, err := os.Stat(dest); err == nil {
			skipped++
			fmt.Printf("  skip  %s (exists)\n", path)
			return nil
		}

		data, err := templates.Personas.ReadFile(path)
		if err != nil {
			return err
		}

		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(dest, data, 0o644); err != nil {
			return err
		}
		created++
		fmt.Printf("  create  %s\n", path)
		return nil
	})
	if err != nil {
		return err
	}

	fmt.Printf("\nInitialized: %d created, %d skipped\n", created, skipped)
	return nil
}
