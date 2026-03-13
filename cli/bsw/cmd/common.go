package cmd

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

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

// currentTmuxSession returns the current tmux session name, or "" if not in tmux.
func currentTmuxSession() string {
	if os.Getenv("TMUX") == "" {
		return ""
	}
	out, err := exec.Command("tmux", "display-message", "-p", "#{session_name}").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// currentTmuxPane returns the current tmux pane ID (e.g. "%42"), or "" if not in tmux.
func currentTmuxPane() string {
	if os.Getenv("TMUX") == "" {
		return ""
	}
	out, err := exec.Command("tmux", "display-message", "-p", "#{pane_id}").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// tmuxSessionValue converts the --session flag value to a TmuxSession for SpawnSpec.
// "new" means create a separate session (empty string). Otherwise pass through.
func tmuxSessionValue(s string) string {
	if s == "new" {
		return ""
	}
	return s
}
