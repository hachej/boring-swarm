package cmd

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"boring-swarm/cli/bsw/defaults"
)

func runInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	project := fs.String("project", ".", "project root")
	force := fs.Bool("force", false, "overwrite default sample files")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	root, err := projectRootFromFlag(*project)
	if err != nil {
		return err
	}

	dirs := []string{
		filepath.Join(root, ".bsw"),
		filepath.Join(root, ".bsw", "logs"),
		filepath.Join(root, ".bsw", "agents"),
		filepath.Join(root, ".bsw", "cursors"),
		filepath.Join(root, ".bsw", "runtime"),
		filepath.Join(root, ".bsw", "prompts"),
		filepath.Join(root, "flows"),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}

	files, err := defaults.Files()
	if err != nil {
		return err
	}
	written := 0
	for _, p := range files {
		b, err := defaults.Read(p)
		if err != nil {
			return err
		}
		dst, err := resolveDefaultTarget(root, p)
		if err != nil {
			return err
		}
		if err := writeDefaultFile(dst, string(b), *force); err != nil {
			return err
		}
		written++
	}

	fmt.Printf("initialized v2 runtime at %s\n", filepath.Join(root, ".bsw"))
	fmt.Printf("copied %d default files into flows/ and .bsw/prompts/\n", written)
	fmt.Printf("default primary flow: %s\n", filepath.Join(root, "flows", "implement_worker_queue.yml"))
	return nil
}

func writeDefaultFile(path, content string, force bool) error {
	if !force {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
	}
	return os.WriteFile(path, []byte(content), 0o644)
}

func resolveDefaultTarget(root, embeddedPath string) (string, error) {
	clean := strings.TrimSpace(embeddedPath)
	if strings.HasPrefix(clean, "prompts/") {
		return filepath.Join(root, ".bsw", clean), nil
	}
	if strings.HasPrefix(clean, "flows/") {
		return filepath.Join(root, clean), nil
	}
	return "", fmt.Errorf("unsupported default path: %s", embeddedPath)
}
