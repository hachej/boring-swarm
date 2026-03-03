package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

const defaultActor = "bsw"

func projectRootFromFlag(project string) (string, error) {
	if project == "" {
		project = "."
	}
	root, err := filepath.Abs(project)
	if err != nil {
		return "", err
	}
	st, err := os.Stat(root)
	if err != nil {
		return "", err
	}
	if !st.IsDir() {
		return "", errors.New("project must be a directory")
	}
	return root, nil
}

func bswDir(projectRoot string) string {
	return filepath.Join(projectRoot, ".bsw")
}

// splitArgs separates a first positional token while preserving all recognized flag tokens.
// It supports interspersed flag placement: `cmd pos --flag value` and `cmd --flag value pos`.
func splitArgs(args []string, valueFlags map[string]bool) (flags []string, positional string, extras []string) {
	i := 0
	for i < len(args) {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flags = append(flags, arg)
			if strings.Contains(arg, "=") {
				i++
				continue
			}
			name := strings.TrimLeft(arg, "-")
			if valueFlags[name] && i+1 < len(args) {
				flags = append(flags, args[i+1])
				i += 2
				continue
			}
			i++
			continue
		}
		if positional == "" {
			positional = arg
		} else {
			extras = append(extras, arg)
		}
		i++
	}
	return flags, positional, extras
}
