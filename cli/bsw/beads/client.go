package beads

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
)

type Client struct {
	Workdir string
	Actor   string
	Bin     string
}

type Issue struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Status      string   `json:"status"`
	Assignee    string   `json:"assignee"`
	Labels      []string `json:"labels"`
	UpdatedAt   string   `json:"updated_at"`
}

type Comment struct {
	ID        int64  `json:"id"`
	IssueID   string `json:"issue_id"`
	Author    string `json:"author"`
	Text      string `json:"text"`
	CreatedAt string `json:"created_at"`
}

func (i Issue) HasLabel(label string) bool {
	for _, l := range i.Labels {
		if strings.EqualFold(strings.TrimSpace(l), strings.TrimSpace(label)) {
			return true
		}
	}
	return false
}

func (c Client) ListByLabel(ctx context.Context, label string) ([]Issue, error) {
	args := []string{"list", "--json", "--limit", "0", "--label", label}
	var out []Issue
	if err := c.runJSON(ctx, args, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c Client) ListByID(ctx context.Context, id string) ([]Issue, error) {
	args := []string{"list", "--json", "--limit", "0", "--id", id, "--all"}
	var out []Issue
	if err := c.runJSON(ctx, args, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c Client) GetIssue(ctx context.Context, id string) (Issue, error) {
	items, err := c.ListByID(ctx, id)
	if err != nil {
		return Issue{}, err
	}
	if len(items) == 0 {
		return Issue{}, fmt.Errorf("bead %s not found", id)
	}
	return items[0], nil
}

func (c Client) Claim(ctx context.Context, id, assignee string) (bool, error) {
	args := []string{"update", id, "--claim", "--actor", assignee, "--json"}
	_, err := c.runRaw(ctx, args)
	if err == nil {
		return true, nil
	}
	var cmdErr *CommandError
	if errors.As(err, &cmdErr) {
		out := strings.ToLower(cmdErr.Output)
		if strings.Contains(out, "already assigned") || strings.Contains(out, "validation failed: claim") {
			return false, nil
		}
	}
	return false, err
}

func (c Client) Transition(ctx context.Context, id, sourceLabel, targetLabel, expectedAssignee, actor string) error {
	issue, err := c.GetIssue(ctx, id)
	if err != nil {
		return err
	}
	if !issue.HasLabel(sourceLabel) {
		return fmt.Errorf("transition precondition failed: missing source label %s", sourceLabel)
	}
	if strings.TrimSpace(issue.Assignee) != strings.TrimSpace(expectedAssignee) {
		return fmt.Errorf("transition precondition failed: assignee=%q expected=%q", issue.Assignee, expectedAssignee)
	}

	args := []string{
		"update", id,
		"--remove-label", sourceLabel,
		"--add-label", targetLabel,
		"--assignee", "",
		"--actor", actor,
		"--json",
	}
	if _, err := c.runRaw(ctx, args); err != nil {
		return err
	}

	post, err := c.GetIssue(ctx, id)
	if err != nil {
		return err
	}
	if post.HasLabel(sourceLabel) {
		return fmt.Errorf("transition verification failed: source label still present")
	}
	if !post.HasLabel(targetLabel) {
		return fmt.Errorf("transition verification failed: target label missing")
	}
	if strings.TrimSpace(post.Assignee) != "" {
		return fmt.Errorf("transition verification failed: assignee not cleared")
	}
	return nil
}

func (c Client) ClearAssigneeIfMatch(ctx context.Context, id, expectedAssignee, actor string) error {
	issue, err := c.GetIssue(ctx, id)
	if err != nil {
		return err
	}
	if strings.TrimSpace(issue.Assignee) != strings.TrimSpace(expectedAssignee) {
		return nil
	}
	_, err = c.runRaw(ctx, []string{"update", id, "--assignee", "", "--actor", actor, "--json"})
	return err
}

func (c Client) AddComment(ctx context.Context, id, text string) error {
	args := []string{"comments", "add", id, text, "--json"}
	if c.Actor != "" {
		args = append(args, "--actor", c.Actor)
	}
	_, err := c.runRaw(ctx, args)
	return err
}

func (c Client) ListComments(ctx context.Context, id string) ([]Comment, error) {
	args := []string{"comments", "list", id, "--json"}
	var out []Comment
	if err := c.runJSON(ctx, args, &out); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (c Client) ReadyIssueIDs(ctx context.Context, label string, unassignedOnly bool) (map[string]struct{}, error) {
	args := readyArgs(label, unassignedOnly)
	out, err := c.runRaw(ctx, args)
	if err != nil {
		return nil, err
	}
	ids := issueIDsFromPayload(out)
	ready := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		ready[id] = struct{}{}
	}
	return ready, nil
}

func readyArgs(label string, unassignedOnly bool) []string {
	args := []string{"ready", "--json", "--limit", "0"}
	if strings.TrimSpace(label) != "" {
		args = append(args, "--label", strings.TrimSpace(label))
	}
	if unassignedOnly {
		args = append(args, "--unassigned")
	}
	return args
}

func (c Client) RobotNextID(ctx context.Context, label string) (string, bool, error) {
	args := []string{"--robot-next"}
	if strings.TrimSpace(label) != "" {
		args = append(args, "--robot-by-label", strings.TrimSpace(label))
	}
	out, err := c.execOnce(ctx, "bv", args)
	if err != nil {
		return "", false, err
	}
	ids := issueIDsFromPayload(out)
	if len(ids) == 0 {
		return "", false, nil
	}
	return ids[0], true, nil
}

func issueIDsFromPayload(raw []byte) []string {
	text := strings.TrimSpace(string(raw))
	if text == "" {
		return nil
	}
	var decoded any
	if err := json.Unmarshal([]byte(text), &decoded); err == nil {
		return dedupeIssueIDs(extractIssueIDsFromAny(decoded))
	}
	return dedupeIssueIDs(extractIssueIDsFromText(text))
}

func extractIssueIDsFromAny(v any) []string {
	switch t := v.(type) {
	case map[string]any:
		out := []string{}
		for _, key := range []string{"id", "issue_id", "bead_id", "issueId", "beadId"} {
			if raw, ok := t[key]; ok {
				s, _ := raw.(string)
				s = strings.TrimSpace(s)
				if looksLikeIssueID(s) {
					out = append(out, s)
				}
			}
		}
		keys := make([]string, 0, len(t))
		for key := range t {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			out = append(out, extractIssueIDsFromAny(t[key])...)
		}
		return out
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			out = append(out, extractIssueIDsFromAny(item)...)
		}
		return out
	default:
		return nil
	}
}

func extractIssueIDsFromText(text string) []string {
	fields := strings.FieldsFunc(text, func(r rune) bool {
		switch {
		case r >= 'a' && r <= 'z':
			return false
		case r >= 'A' && r <= 'Z':
			return false
		case r >= '0' && r <= '9':
			return false
		case r == '-', r == '_', r == '.':
			return false
		default:
			return true
		}
	})
	out := make([]string, 0, len(fields))
	for _, field := range fields {
		if looksLikeIssueID(field) {
			out = append(out, strings.TrimSpace(field))
		}
	}
	return out
}

func dedupeIssueIDs(items []string) []string {
	if len(items) <= 1 {
		return items
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(items))
	for _, item := range items {
		id := strings.TrimSpace(item)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

func looksLikeIssueID(v string) bool {
	s := strings.ToLower(strings.TrimSpace(v))
	return strings.HasPrefix(s, "bd-") && len(s) > 3
}

func (c Client) runJSON(ctx context.Context, args []string, v any) error {
	out, err := c.runRaw(ctx, args)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(out, v); err != nil {
		return fmt.Errorf("decode br json for %v: %w; output=%s", args, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (c Client) runRaw(ctx context.Context, args []string) ([]byte, error) {
	bin := c.Bin
	if strings.TrimSpace(bin) == "" {
		bin = "br"
	}
	runArgs := c.withBRGlobalFlags(args)
	out, err := c.execOnce(ctx, bin, runArgs)
	if err == nil {
		return out, nil
	}
	// Retry once without bsw-added global flags when the flags are unsupported
	// or when no-auto-import mode causes JSONL/DB freshness desync.
	var cmdErr *CommandError
	if errors.As(err, &cmdErr) && len(runArgs) != len(args) {
		if unsupportedGlobalFlags(cmdErr.Output) || autoImportDisabledDesync(cmdErr.Output) {
			out2, err2 := c.execOnce(ctx, bin, args)
			if err2 == nil {
				return out2, nil
			}
			return nil, err2
		}
	}
	return nil, err
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

func (c Client) withBRGlobalFlags(args []string) []string {
	// Keep writes DB-first and avoid flush coupling by default. Do NOT disable
	// auto-import here; workers and runner transitions can legitimately make
	// JSONL newer than DB between cycles.
	if !useSQLiteNativeBR() {
		return args
	}
	out := make([]string, 0, len(args)+1)
	out = append(out, "--no-auto-flush")
	out = append(out, args...)
	return out
}

func useSQLiteNativeBR() bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv("BSW_BR_SQLITE_NATIVE")))
	switch v {
	case "", "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return true
	}
}

func unsupportedGlobalFlags(output string) bool {
	lower := strings.ToLower(strings.TrimSpace(output))
	if lower == "" {
		return false
	}
	if !strings.Contains(lower, "no-auto-import") && !strings.Contains(lower, "no-auto-flush") {
		return false
	}
	return strings.Contains(lower, "unexpected argument") ||
		strings.Contains(lower, "unrecognized option") ||
		strings.Contains(lower, "unknown option") ||
		strings.Contains(lower, "found argument")
}

func autoImportDisabledDesync(output string) bool {
	lower := strings.ToLower(strings.TrimSpace(output))
	if lower == "" {
		return false
	}
	return strings.Contains(lower, "jsonl is newer than the database") &&
		strings.Contains(lower, "auto-import disabled")
}

type CommandError struct {
	Args     []string
	ExitCode int
	Output   string
}

func (e *CommandError) Error() string {
	return "br " + strings.Join(e.Args, " ") + " failed with exit " + strconv.Itoa(e.ExitCode) + ": " + strings.TrimSpace(e.Output)
}
