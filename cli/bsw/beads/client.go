package beads

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

type Client struct {
	Workdir string
	Bin     string
}

type Issue struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Status      string   `json:"status"`
	Assignee    string   `json:"assignee"`
	Labels      []string `json:"labels"`
}

// List returns all open beads (limited to limit, 0 = all).
func (c Client) List(ctx context.Context, limit int) ([]Issue, error) {
	args := []string{"list", "--json", "--limit", strconv.Itoa(limit)}
	var out []Issue
	if err := c.runJSON(ctx, args, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c Client) ListByLabel(ctx context.Context, label string) ([]Issue, error) {
	args := []string{"list", "--json", "--limit", "0", "--label", label}
	var out []Issue
	if err := c.runJSON(ctx, args, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c Client) ClearAssignee(ctx context.Context, id string) error {
	_, err := c.runRaw(ctx, []string{"update", id, "--assignee", ""})
	return err
}

func (c Client) runJSON(ctx context.Context, args []string, v any) error {
	out, err := c.runRaw(ctx, args)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(out, v); err != nil {
		return fmt.Errorf("decode br json: %w; output=%s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (c Client) runRaw(ctx context.Context, args []string) ([]byte, error) {
	bin := c.Bin
	if strings.TrimSpace(bin) == "" {
		bin = "br"
	}
	return c.execOnce(ctx, bin, args)
}

func (c Client) execOnce(ctx context.Context, bin string, args []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	if strings.TrimSpace(c.Workdir) != "" {
		cmd.Dir = c.Workdir
	}
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		code := 1
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			code = exitErr.ExitCode()
		}
		all := strings.TrimSpace(strings.Join([]string{stdout.String(), stderr.String()}, "\n"))
		if all == "" {
			all = strings.TrimSpace(err.Error())
		}
		return nil, &CommandError{Args: append([]string(nil), args...), ExitCode: code, Output: all}
	}
	return stdout.Bytes(), nil
}

type CommandError struct {
	Args     []string
	ExitCode int
	Output   string
}

func (e *CommandError) Error() string {
	return "br " + strings.Join(e.Args, " ") + " failed with exit " + strconv.Itoa(e.ExitCode) + ": " + strings.TrimSpace(e.Output)
}
