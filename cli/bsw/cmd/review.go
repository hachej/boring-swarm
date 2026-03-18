package cmd

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

const defaultReviewTimeout = 90 * time.Second

func runReview(args []string) error {
	fs := flag.NewFlagSet("review", flag.ContinueOnError)
	provider := fs.String("provider", "", "provider to use for review (roborev, claude, gemini, codex). Auto-detects if omitted.")
	model := fs.String("model", "", "model override for the review")
	project := fs.String("project", ".", "project root directory")
	files := fs.String("files", "", "comma-separated list of files to review (scopes diff to only these files)")
	bead := fs.String("bead", "", "bead ID — auto-extracts file list from bead's FILES: comments")
	timeoutSec := fs.Int("timeout", 90, "review timeout in seconds (0 = no timeout)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	prompt := strings.Join(fs.Args(), " ")
	if prompt == "" {
		prompt = "Check correctness, test coverage, and edge cases. Reply PASS or FAIL: <findings>"
	}

	root, err := projectRootFromFlag(*project)
	if err != nil {
		return err
	}

	timeout := time.Duration(*timeoutSec) * time.Second
	if *timeoutSec == 0 {
		timeout = 0
	}

	// Parse file list: -bead takes priority (reads from bead metadata), then -files
	var fileList []string
	if *bead != "" {
		fileList = filesFromBead(root, *bead)
		if len(fileList) > 0 {
			fmt.Fprintf(os.Stderr, "bsw review: found %d files from bead %s\n", len(fileList), *bead)
		} else {
			fmt.Fprintf(os.Stderr, "bsw review: no FILES: comment on bead %s, reviewing all changes\n", *bead)
		}
	} else if *files != "" {
		for _, f := range strings.Split(*files, ",") {
			f = strings.TrimSpace(f)
			if f != "" {
				fileList = append(fileList, f)
			}
		}
	}

	p := *provider
	if p == "" {
		p = detectReviewProvider()
	}

	fmt.Fprintf(os.Stderr, "bsw review: using %s", p)
	if timeout > 0 {
		fmt.Fprintf(os.Stderr, " (timeout %ds)", *timeoutSec)
	}
	if len(fileList) > 0 {
		fmt.Fprintf(os.Stderr, " [%d files]", len(fileList))
	}
	fmt.Fprintln(os.Stderr)

	var reviewErr error
	switch p {
	case "roborev":
		reviewErr = runRoborevReview(root, *model, prompt, fileList, timeout)
	case "codex":
		reviewErr = runCodexReview(root, *model, prompt, timeout)
	case "claude":
		reviewErr = runClaudeReview(root, *model, prompt, fileList, timeout)
	case "gemini":
		reviewErr = runGeminiReview(root, *model, prompt, fileList, timeout)
	default:
		return fmt.Errorf("unsupported review provider %q (use roborev, claude, gemini, or codex)", p)
	}

	if reviewErr != nil && isTimeout(reviewErr) {
		fmt.Fprintln(os.Stderr, "bsw review: TIMEOUT — review did not complete in time. Inspect manually before closing bead.")
		return fmt.Errorf("review timed out after %ds", *timeoutSec)
	}
	return reviewErr
}

func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	if err == context.DeadlineExceeded {
		return true
	}
	return strings.Contains(err.Error(), "signal: killed")
}

func detectReviewProvider() string {
	// Prefer roborev (best quality, ~30s), then claude (fastest, ~7s), then gemini, then codex
	// codex review is thorough but slow (MCP init overhead makes it 90s+)
	if _, err := exec.LookPath("roborev"); err == nil {
		return "roborev"
	}
	if _, err := exec.LookPath("claude"); err == nil {
		return "claude"
	}
	if _, err := exec.LookPath("gemini"); err == nil {
		return "gemini"
	}
	if _, err := exec.LookPath("codex"); err == nil {
		return "codex"
	}
	return "claude" // fallback
}

func withTimeout(timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout > 0 {
		return context.WithTimeout(context.Background(), timeout)
	}
	return context.Background(), func() {}
}

func runRoborevReview(root, model, prompt string, fileList []string, timeout time.Duration) error {
	// roborev --dirty cannot scope to specific files.
	// When files are specified (multi-agent), fall back to claude with scoped diff.
	if len(fileList) > 0 {
		fmt.Fprintln(os.Stderr, "bsw review: roborev cannot scope to files, falling back to claude for scoped review")
		return runClaudeReview(root, model, prompt, fileList, timeout)
	}

	bin := providerBinaryLookup("roborev")
	ctx, cancel := withTimeout(timeout)
	defer cancel()

	args := []string{"review", "--dirty", "--wait", "--fast", "--local"}
	if model != "" {
		args = append(args, "--model", model)
	}

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = root
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func runCodexReview(root, model, prompt string, timeout time.Duration) error {
	bin := providerBinaryLookup("codex")
	ctx, cancel := withTimeout(timeout)
	defer cancel()

	// codex review --uncommitted reviews all uncommitted changes (cannot scope to files).
	args := []string{"review", "--uncommitted"}
	if model != "" {
		args = append(args, "--model", model)
	}
	if prompt != "" {
		args = append(args, "--title", prompt)
	}

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = root
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Strip MCP env vars so codex doesn't auto-discover servers (major speedup)
	cmd.Env = filterEnvKeys(os.Environ(), "AGENT_MAIL", "MCP_")
	return cmd.Run()
}

func runClaudeReview(root, model, prompt string, fileList []string, timeout time.Duration) error {
	bin := providerBinaryLookup("claude")
	ctx, cancel := withTimeout(timeout)
	defer cancel()

	// Get diff scoped to specific files if provided
	diffOut := gitDiff(root, fileList)
	stdinContent := fmt.Sprintf("Review these changes. %s\n\n```diff\n%s\n```", prompt, diffOut)

	args := []string{"-p", "--dangerously-skip-permissions", "--no-session-persistence"}
	if model != "" {
		args = append(args, "--model", model)
	}
	args = append(args, "-") // read prompt from stdin

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = root
	cmd.Stdin = strings.NewReader(stdinContent)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func runGeminiReview(root, model, prompt string, fileList []string, timeout time.Duration) error {
	bin := providerBinaryLookup("gemini")
	ctx, cancel := withTimeout(timeout)
	defer cancel()

	// Get diff scoped to specific files if provided
	diffOut := gitDiff(root, fileList)
	stdinContent := fmt.Sprintf("```diff\n%s\n```", diffOut)
	geminiPrompt := fmt.Sprintf("Review these uncommitted changes. %s", prompt)

	args := []string{"-p", geminiPrompt}
	if model != "" {
		args = append(args, "-m", model)
	}

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = root
	cmd.Stdin = strings.NewReader(stdinContent)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// filesFromBead extracts the file list from a bead's comments.
// Looks for comments starting with "FILES:" and parses the file paths.
func filesFromBead(root, beadID string) []string {
	cmd := exec.Command("br", "comments", "list", beadID, "--json")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		return nil
	}

	// Parse JSON array of comments, look for FILES: lines
	type comment struct {
		Text string `json:"text"`
	}
	var comments []comment
	if err := json.Unmarshal(out, &comments); err != nil {
		return nil
	}

	// Find the most recent FILES: comment
	var filesText string
	for _, c := range comments {
		if strings.HasPrefix(c.Text, "FILES:") {
			filesText = strings.TrimPrefix(c.Text, "FILES:")
		}
	}
	if filesText == "" {
		return nil
	}

	// Parse space/newline-separated file paths
	var files []string
	for _, f := range strings.Fields(filesText) {
		f = strings.TrimSpace(f)
		if f != "" {
			files = append(files, f)
		}
	}
	return files
}

// gitDiff returns the uncommitted diff, optionally scoped to specific files.
// In multi-agent swarms, passing fileList limits the review to only the calling worker's files.
func gitDiff(root string, fileList []string) string {
	args := []string{"diff", "HEAD"}
	if len(fileList) > 0 {
		args = append(args, "--")
		args = append(args, fileList...)
	}
	cmd := exec.Command("git", args...)
	cmd.Dir = root
	out, _ := cmd.Output()
	return string(out)
}

// providerBinaryLookup checks env override then falls back to binary name.
func providerBinaryLookup(provider string) string {
	envKey := "BSW_" + strings.ToUpper(provider) + "_BIN"
	if v := strings.TrimSpace(os.Getenv(envKey)); v != "" {
		return v
	}
	return provider
}

// filterEnvKeys returns env with entries matching any prefix removed.
func filterEnvKeys(env []string, prefixes ...string) []string {
	out := make([]string, 0, len(env))
	for _, e := range env {
		idx := strings.IndexByte(e, '=')
		if idx <= 0 {
			out = append(out, e)
			continue
		}
		key := strings.ToUpper(e[:idx])
		drop := false
		for _, p := range prefixes {
			if strings.HasPrefix(key, strings.ToUpper(p)) {
				drop = true
				break
			}
		}
		if !drop {
			out = append(out, e)
		}
	}
	return out
}
