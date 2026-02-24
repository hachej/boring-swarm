package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/pelletier/go-toml/v2"
	"gopkg.in/yaml.v3"
)

const (
	defaultConfigPath  = ".bsw/config.json"
	defaultMetaPath    = ".bsw/swarm.toml"
	defaultFlowPath    = ".bsw/flow.toml"
	legacyFlowPathYML  = ".bsw/flow.yml"
	legacyFlowPathYAML = ".bsw/flow.yaml"
	defaultActor       = "bsw"
	tmuxFieldSep       = "_BSW_SEP_"
)

var (
	workerTitlePattern = regexp.MustCompile(`^(.+):(implement|proof|review|committer|plan-review):(\d+)$`)
	uuidInFilename     = regexp.MustCompile(`([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\.jsonl$`)
	swarmBeaconLine    = regexp.MustCompile(`(?mi)^\s*SWARM_STATUS\b.*$`)
	stateLinePattern   = regexp.MustCompile(`(?mi)^\s*state:\s*([a-z]+:[a-z_]+)\b`)
	shellCommands      = map[string]bool{
		"bash": true,
		"zsh":  true,
		"sh":   true,
		"fish": true,
	}
	paneStyleCache = map[string]string{}
)

type Config struct {
	Session     string           `json:"session"`
	ProjectRoot string           `json:"project_root"`
	Actor       string           `json:"actor"`
	PollSeconds int              `json:"poll_seconds"`
	IdleSeconds int              `json:"idle_seconds"`
	Roles       []RoleConfig     `json:"roles"`
	AgentMail   AgentMailConfig  `json:"agent_mail"`
	PlanReview  PlanReviewConfig `json:"plan_reviewer"`
}

type AgentMailConfig struct {
	Enabled      bool   `json:"enabled"`
	AutoRegister bool   `json:"auto_register"`
	URL          string `json:"url"`
	Token        string `json:"token"`
}

type PlanReviewConfig struct {
	Enabled       bool   `json:"enabled"`
	Provider      string `json:"provider"`
	Model         string `json:"model"`
	Effort        string `json:"effort"`
	PromptFile    string `json:"prompt_file"`
	LaunchCommand string `json:"launch_command"`
}

type SwarmMeta struct {
	PlanFile string
	Topics   []string
}

type stringSliceFlag []string

func (s *stringSliceFlag) String() string {
	return strings.Join(*s, ",")
}

type FlowSpec struct {
	Version     int              `toml:"version" yaml:"version"`
	Start       string           `toml:"start" yaml:"start"`
	States      []FlowState      `toml:"states" yaml:"states"`
	Transitions []FlowTransition `toml:"transitions" yaml:"transitions"`
}

type FlowState struct {
	ID                     string `toml:"id" yaml:"id"`
	Kind                   string `toml:"kind" yaml:"kind"`
	Label                  string `toml:"label" yaml:"label"`
	Prompt                 string `toml:"prompt" yaml:"prompt"`
	Provider               string `toml:"provider" yaml:"provider"`
	Model                  string `toml:"model" yaml:"model"`
	Effort                 string `toml:"effort" yaml:"effort"`
	Workers                int    `toml:"workers" yaml:"workers"`
	MaxIdle                string `toml:"max_idle" yaml:"max_idle"`
	MaxLifetime            string `toml:"max_lifetime" yaml:"max_lifetime"`
	MaxBusyWithoutProgress string `toml:"max_busy_without_progress" yaml:"max_busy_without_progress"`
	Respawn                string `toml:"respawn" yaml:"respawn"`
	OneShot                string `toml:"one_shot" yaml:"one_shot"`
	ColorBG                string `toml:"color_bg" yaml:"color_bg"`
	ColorFG                string `toml:"color_fg" yaml:"color_fg"`
	TmuxBG                 string `toml:"tmux_bg" yaml:"tmux_bg"`
	TmuxFG                 string `toml:"tmux_fg" yaml:"tmux_fg"`
}

type WorkerLifecyclePolicy struct {
	Workers                int
	MaxIdle                time.Duration
	MaxLifetime            time.Duration
	MaxBusyWithoutProgress time.Duration
	Respawn                bool
	OneShot                bool
}

type FlowTransition struct {
	From    string   `toml:"from" yaml:"from"`
	On      string   `toml:"on" yaml:"on"`
	To      string   `toml:"to" yaml:"to"`
	Guard   string   `toml:"guard" yaml:"guard"`
	Actions []string `toml:"actions" yaml:"actions"`
}

func (s *stringSliceFlag) Set(v string) error {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	*s = append(*s, v)
	return nil
}

type RoleConfig struct {
	Name           string `json:"name"`
	Label          string `json:"label"`
	Workers        int    `json:"workers"`
	Provider       string `json:"provider"`
	Model          string `json:"model"`
	Effort         string `json:"effort"`
	PromptFile     string `json:"prompt_file"`
	LaunchCommand  string `json:"launch_command"`
	TranscriptGlob string `json:"transcript_glob"`
}

type Bead struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Status      string   `json:"status"`
	Priority    int      `json:"priority"`
	Labels      []string `json:"labels"`
	Assignee    string   `json:"assignee"`
	Owner       string   `json:"owner"`
	CreatedAt   string   `json:"created_at"`
	UpdatedAt   string   `json:"updated_at"`
}

type Pane struct {
	Session        string
	PaneID         string
	PaneIndex      int
	PaneTitle      string
	CurrentCommand string
	StartAt        time.Time
	ActivityAt     time.Time
	LastLine       string
}

type WorkerRef struct {
	Session  string
	WorkerID string
	Role     string
	Index    int
}

type WorkerStatus struct {
	Session        string
	WorkerID       string
	AgentName      string
	Role           string
	Pane           int
	Provider       string
	Model          string
	Effort         string
	State          string
	BeadID         string
	BeadTitle      string
	Label          string
	StartedAt      time.Time
	Duration       time.Duration
	ActivityAge    time.Duration
	TokenPerMinute float64
	TranscriptAge  time.Duration
	Activity       string
	Reason         string
}

type WorkerRuntimeFile struct {
	Workers map[string]WorkerRuntime `json:"workers"`
}

type WorkerRuntime struct {
	WorkerID         string `json:"worker_id"`
	Provider         string `json:"provider"`
	SessionID        string `json:"session_id,omitempty"`
	TranscriptPath   string `json:"transcript_path,omitempty"`
	LaunchedAt       string `json:"launched_at,omitempty"`
	LastNudgeAt      string `json:"last_nudge_at,omitempty"`
	LastNudgeBead    string `json:"last_nudge_bead,omitempty"`
	LastReleasedAt   string `json:"last_released_at,omitempty"`
	LastReleasedBead string `json:"last_released_bead,omitempty"`
	CommitBeadID     string `json:"commit_bead_id,omitempty"`
	CommitStartedAt  string `json:"commit_started_at,omitempty"`
}

type CommitQueueFile struct {
	Pending []CommitJob `json:"pending"`
}

type CommitJob struct {
	BeadID     string `json:"bead_id"`
	EnqueuedAt string `json:"enqueued_at"`
}

type CodexSessionMeta struct {
	ID        string
	CWD       string
	StartedAt time.Time
}

type WorkflowStageCounts struct {
	InImplementation int
	InProof          int
	InReview         int
	QueueImpl        int
	QueueProof       int
	QueueReview      int
	AssignedImpl     int
	AssignedProof    int
	AssignedReview   int
	AssignedOther    int
	Unassigned       int
}

type LifecycleCounts struct {
	ActiveBeads          int
	ProofRejectBeads     int
	ReviewRejectBeads    int
	ProofRejectEvents    int
	ReviewRejectEvents   int
	ProofPassEvents      int
	ReviewPassEvents     int
	ImplementationEvents int
}

type LifecycleBeadRow struct {
	ID             string
	Title          string
	Stage          string
	Status         string
	Assignee       string
	Current        string
	Timeline       []string
	ImplDone       int
	ProofFailed    int
	ProofPassed    int
	ReviewFailed   int
	ReviewPassed   int
	LastState      string
	History        []string
	HistoryPreview string
}

type SwarmBeacon struct {
	Role   string
	State  string
	BeadID string
	Reason string
	At     time.Time
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "init":
		err = runInit(args)
	case "spawn":
		err = runSpawn(args)
	case "attach":
		err = runAttach(args)
	case "add":
		err = runAdd(args)
	case "tick", "tock":
		err = runTick(args)
	case "daemon":
		err = runDaemon(args)
	case "robot":
		err = runRobot(args)
	case "doctor":
		err = runDoctor(args)
	case "status", "sessions":
		err = runStatus(args)
	case "tui":
		err = runTUI(args)
	case "zoom":
		err = runZoom(args)
	case "help", "-h", "--help":
		printUsage()
		return
	default:
		err = fmt.Errorf("unknown command %q", cmd)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`bsw - simple bead-native implement/proof/review harness

Usage:
  bsw init   [--config .bsw/config.json] [--force]
  bsw spawn  [--config .bsw/config.json]
  bsw attach [--config .bsw/config.json] [--plan <path>] [--topic <name> ...]
  bsw add    --role <implement|proof|review> [--count 1] [--config .bsw/config.json]
  bsw tick   [--config .bsw/config.json]
  bsw tock   [--config .bsw/config.json]   # alias of tick
  bsw daemon [--config .bsw/config.json] [--once] [--poll 5]
  bsw robot  [--config .bsw/config.json] [--once]
  bsw doctor [--config .bsw/config.json]
  bsw status [--config .bsw/config.json]
  bsw sessions [--config .bsw/config.json] # alias of status
  bsw tui    [--config .bsw/config.json] [--refresh 1]
  bsw zoom   --session <name> --pane <index>

Process (recommended):
1) Initialize project scaffolding (config + flow + prompts):
   bsw init

2) Attach execution context (single active plan + optional topics):
   bsw attach --plan docs/exec-plans/active/<plan>.md --topic <t1> --topic <t2>
   Notes:
   - only one plan_file is attached at a time
   - topics are metadata/context for plan-review (not assignment filters)

3) Create/ensure worker panes for current session:
   bsw spawn

4) Start orchestration loop:
   bsw daemon --mode hybrid
   (or one cycle only: bsw tick / bsw tock)

5) Observe and inspect:
   bsw tui
   bsw status

Swarm session model:
- tmux session name comes from .bsw/config.json -> session
- to run a separate swarm, use a different session name (or separate worktree)
- when changing plans in same project, stop old daemon, then re-attach:
  bsw attach --plan <new-plan>

State and transitions:
- source of truth is beads (labels/assignee/comments/STATE markers)
- queue labels: needs-impl, needs-proof, needs-review
- default flow: implement -> proof -> review
- plan-review is triggered when no active bead work remains

Runtime behaviors:
- daemon can assign, nudge, and recycle panes based on lifecycle policy
- transcript + beacon signals are used for activity/status inference
- agent-mail registration can happen automatically on worker launch

Design:
- Assignment state lives in beads only (assignee/owner/labels/comments).
- Worker roles are strict: implement, proof, review.
- Declarative state machine lives in .bsw/flow.toml.
- Optional transcript metrics from role.transcript_glob (codex/claude JSONL).
- Optional Agent Mail auto-register on worker launch.`)
}

func runRobot(args []string) error {
	defaults := []string{
		"--mode", "hybrid",
		"--sensor", "1",
		"--debounce-ms", "250",
		"--fallback", "10",
		"--poll", "4",
	}
	fmt.Println("[robot] mode=hybrid sensor=1s debounce=250ms fallback=10s poll=4s")
	return runDaemon(append(defaults, args...))
}

func runDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	configPath := fs.String("config", defaultConfigPath, "path to config")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		return err
	}
	if err := validateConfig(cfg); err != nil {
		return err
	}

	type check struct {
		name string
		err  error
	}
	var checks []check
	mustFile := func(path string) error {
		_, err := os.Stat(path)
		if err != nil {
			return err
		}
		return nil
	}
	mustCmd := func(name string) error {
		_, err := exec.LookPath(name)
		return err
	}

	flowPath := effectiveFlowPath(cfg.ProjectRoot)
	checks = append(checks, check{name: "config", err: nil})
	checks = append(checks, check{name: "flow.file", err: mustFile(flowPath)})
	if flow, ferr := loadFlowSpec(cfg.ProjectRoot); ferr != nil {
		checks = append(checks, check{name: "flow.parse", err: ferr})
	} else {
		if len(flow.States) == 0 {
			checks = append(checks, check{name: "flow.states", err: errors.New("no states defined")})
		}
		if len(flow.Transitions) == 0 {
			checks = append(checks, check{name: "flow.transitions", err: errors.New("no transitions defined")})
		}
	}

	for _, role := range cfg.Roles {
		p := strings.TrimSpace(expandHome(role.PromptFile))
		checks = append(checks, check{name: "prompt:" + role.Name, err: mustFile(p)})
	}
	if cfg.PlanReview.Enabled {
		p := strings.TrimSpace(expandHome(cfg.PlanReview.PromptFile))
		checks = append(checks, check{name: "prompt:plan-review", err: mustFile(p)})
	}

	checks = append(checks,
		check{name: "dep:tmux", err: mustCmd("tmux")},
		check{name: "dep:br", err: mustCmd("br")},
		check{name: "dep:ntm", err: mustCmd("ntm")},
	)
	needCodex := false
	needCC := false
	for _, r := range cfg.Roles {
		switch normalizeProvider(r.Provider) {
		case "codex":
			needCodex = true
		case "cc":
			needCC = true
		}
	}
	if needCodex {
		checks = append(checks, check{name: "dep:codex", err: mustCmd("codex")})
	}
	if needCC {
		checks = append(checks, check{name: "dep:cc", err: mustCmd("cc")})
	}

	failed := 0
	fmt.Printf("doctor: project=%s session=%s\n", cfg.ProjectRoot, cfg.Session)
	for _, c := range checks {
		if c.err != nil {
			failed++
			fmt.Printf("  FAIL %-18s %v\n", c.name, c.err)
		} else {
			fmt.Printf("  OK   %s\n", c.name)
		}
	}
	if failed > 0 {
		return fmt.Errorf("doctor found %d issue(s)", failed)
	}
	fmt.Println("doctor: all checks passed")
	return nil
}

func runInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	configPath := fs.String("config", defaultConfigPath, "path to config")
	force := fs.Bool("force", false, "overwrite config")
	plan := fs.String("plan", "", "plan file path to attach to swarm")
	var topics stringSliceFlag
	fs.Var(&topics, "topic", "topic to attach to swarm (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	projectRoot, err := inferProjectRoot(cwd)
	if err != nil {
		return err
	}

	cfgPath := *configPath
	if !filepath.IsAbs(cfgPath) {
		cfgPath = filepath.Join(cwd, cfgPath)
	}
	if _, err := os.Stat(cfgPath); err == nil && !*force {
		return fmt.Errorf("config already exists at %s (use --force)", cfgPath)
	}

	promptsRoot := filepath.Join(projectRoot, ".bsw", "prompts")
	if err := writeDefaultPromptSet(promptsRoot); err != nil {
		return err
	}
	cfg := Config{
		Session:     fmt.Sprintf("%s-bsw", slug(filepath.Base(projectRoot))),
		ProjectRoot: projectRoot,
		Actor:       defaultActor,
		PollSeconds: 5,
		IdleSeconds: 20,
		Roles: []RoleConfig{
			{
				Name:           "implement",
				Label:          "needs-impl",
				Workers:        1,
				Provider:       "codex",
				Model:          "gpt-5.3-codex",
				Effort:         "medium",
				PromptFile:     filepath.Join(promptsRoot, "impl_worker.md"),
				LaunchCommand:  "",
				TranscriptGlob: "~/.codex/sessions/*/*/*/rollout-*.jsonl",
			},
			{
				Name:           "proof",
				Label:          "needs-proof",
				Workers:        1,
				Provider:       "cc",
				Model:          "opus",
				Effort:         "high",
				PromptFile:     filepath.Join(promptsRoot, "impl_proofer.md"),
				LaunchCommand:  "",
				TranscriptGlob: "~/.claude/projects/*/*.jsonl",
			},
			{
				Name:           "review",
				Label:          "needs-review",
				Workers:        1,
				Provider:       "cc",
				Model:          "opus",
				Effort:         "high",
				PromptFile:     filepath.Join(promptsRoot, "impl_reviewer.md"),
				LaunchCommand:  "",
				TranscriptGlob: "~/.claude/projects/*/*.jsonl",
			},
			{
				Name:           "committer",
				Label:          "commit-queue",
				Workers:        1,
				Provider:       "cc",
				Model:          "opus",
				Effort:         "medium",
				PromptFile:     filepath.Join(promptsRoot, "impl_committer.md"),
				LaunchCommand:  "",
				TranscriptGlob: "~/.claude/projects/*/*.jsonl",
			},
		},
		AgentMail: AgentMailConfig{
			Enabled:      true,
			AutoRegister: true,
			URL:          firstNonEmpty(os.Getenv("AGENT_MAIL_URL"), "http://127.0.0.1:8765/mcp"),
			Token:        os.Getenv("AGENT_MAIL_TOKEN"),
		},
		PlanReview: PlanReviewConfig{
			Enabled:       true,
			Provider:      "cc",
			Model:         "opus",
			Effort:        "high",
			PromptFile:    filepath.Join(promptsRoot, "plan_reviewer.md"),
			LaunchCommand: "",
		},
	}

	if err := writeJSON(cfgPath, cfg); err != nil {
		return err
	}

	fmt.Printf("initialized config: %s\n", cfgPath)
	fmt.Printf("prompt refs:\n")
	for _, role := range cfg.Roles {
		fmt.Printf("  %s -> %s\n", role.Name, role.PromptFile)
	}
	metaPath := filepath.Join(projectRoot, defaultMetaPath)
	meta := SwarmMeta{
		PlanFile: strings.TrimSpace(*plan),
		Topics:   append([]string(nil), topics...),
	}
	if err := writeSwarmMeta(metaPath, meta); err != nil {
		return err
	}
	if meta.PlanFile != "" || len(meta.Topics) > 0 {
		fmt.Printf("attached swarm meta: %s\n", metaPath)
	}
	flowPath := filepath.Join(projectRoot, defaultFlowPath)
	if err := writeDefaultFlowTOML(flowPath); err != nil {
		return err
	}
	fmt.Printf("initialized flow: %s\n", flowPath)
	return nil
}

func runAttach(args []string) error {
	fs := flag.NewFlagSet("attach", flag.ContinueOnError)
	configPath := fs.String("config", defaultConfigPath, "path to config")
	plan := fs.String("plan", "", "plan file path")
	var topics stringSliceFlag
	fs.Var(&topics, "topic", "topic (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		return err
	}
	if err := validateConfig(cfg); err != nil {
		return err
	}

	metaPath := filepath.Join(cfg.ProjectRoot, defaultMetaPath)
	meta, _ := loadSwarmMeta(cfg.ProjectRoot)
	if strings.TrimSpace(*plan) != "" {
		meta.PlanFile = strings.TrimSpace(*plan)
	}
	if len(topics) > 0 {
		meta.Topics = append([]string(nil), topics...)
	}
	if err := writeSwarmMeta(metaPath, meta); err != nil {
		return err
	}
	fmt.Printf("updated swarm meta: %s\n", metaPath)
	if meta.PlanFile != "" {
		fmt.Printf("  plan: %s\n", meta.PlanFile)
	}
	if len(meta.Topics) > 0 {
		fmt.Printf("  topics: %s\n", strings.Join(meta.Topics, ", "))
	}
	return nil
}

func runSpawn(args []string) error {
	fs := flag.NewFlagSet("spawn", flag.ContinueOnError)
	configPath := fs.String("config", defaultConfigPath, "path to config")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		return err
	}
	if err := validateConfig(cfg); err != nil {
		return err
	}

	if err := ensureSessionAndPanes(cfg); err != nil {
		return err
	}

	fmt.Printf("session ready: %s\n", cfg.Session)
	return nil
}

func runAdd(args []string) error {
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	configPath := fs.String("config", defaultConfigPath, "path to config")
	roleName := fs.String("role", "", "role name to scale (implement|proof|review)")
	count := fs.Int("count", 1, "number of workers to add")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*roleName) == "" {
		return errors.New("add requires --role")
	}
	if *count <= 0 {
		*count = 1
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		return err
	}
	if err := validateConfig(cfg); err != nil {
		return err
	}

	roleIdx := -1
	for i := range cfg.Roles {
		if strings.EqualFold(strings.TrimSpace(cfg.Roles[i].Name), strings.TrimSpace(*roleName)) {
			roleIdx = i
			break
		}
	}
	if roleIdx < 0 {
		available := make([]string, 0, len(cfg.Roles))
		for _, r := range cfg.Roles {
			available = append(available, r.Name)
		}
		return fmt.Errorf("unknown role %q (available: %s)", *roleName, strings.Join(available, ", "))
	}

	before := cfg.Roles[roleIdx].Workers
	cfg.Roles[roleIdx].Workers = before + *count

	cfgPath := *configPath
	if !filepath.IsAbs(cfgPath) {
		cwd, err := os.Getwd()
		if err != nil {
			return err
		}
		cfgPath = filepath.Join(cwd, cfgPath)
	}
	if err := writeJSON(cfgPath, cfg); err != nil {
		return err
	}
	if err := ensureAddedRoleWorkers(cfg, cfg.Roles[roleIdx], before+1, cfg.Roles[roleIdx].Workers); err != nil {
		return err
	}
	addedWorkers := make([]string, 0, *count)
	for idx := before + 1; idx <= cfg.Roles[roleIdx].Workers; idx++ {
		addedWorkers = append(addedWorkers, workerID(cfg.Session, cfg.Roles[roleIdx].Name, idx))
	}
	initSent := 0
	for _, wid := range addedWorkers {
		if err := sendInitPromptToWorker(cfg, cfg.Roles[roleIdx], wid, 10*time.Second); err != nil {
			fmt.Fprintf(os.Stderr, "warning: init prompt skipped for %s: %v\n", wid, err)
			continue
		}
		initSent++
	}

	rows, err := collectStatuses(cfg, false)
	if err != nil {
		return err
	}
	fmt.Printf("scaled role %s: workers %d -> %d\n", cfg.Roles[roleIdx].Name, before, cfg.Roles[roleIdx].Workers)
	fmt.Printf("session: %s\n", cfg.Session)
	for _, r := range rows {
		if !strings.EqualFold(r.Role, cfg.Roles[roleIdx].Name) {
			continue
		}
		bead := r.BeadID
		if bead == "" {
			bead = "-"
		}
		fmt.Printf("  pane=%d worker=%s agent=%s state=%s bead=%s provider=%s model=%s\n",
			r.Pane, r.WorkerID, r.AgentName, r.State, bead, r.Provider, r.Model)
	}
	fmt.Printf("init prompts sent: %d/%d\n", initSent, len(addedWorkers))
	return nil
}

func ensureAddedRoleWorkers(cfg Config, role RoleConfig, startIdx, endIdx int) error {
	if startIdx > endIdx {
		return nil
	}
	if !tmuxSessionExists(cfg.Session) {
		if _, err := runCommand("", "tmux", "new-session", "-d", "-s", cfg.Session, "-n", "swarm"); err != nil {
			return err
		}
	}

	panes, err := listPanes(cfg.Session, false)
	if err != nil {
		return err
	}
	paneByTitle := map[string]Pane{}
	for _, p := range panes {
		paneByTitle[p.PaneTitle] = p
	}

	for idx := startIdx; idx <= endIdx; idx++ {
		wid := workerID(cfg.Session, role.Name, idx)
		if existing, ok := paneByTitle[wid]; ok {
			if shellCommands[strings.ToLower(strings.TrimSpace(existing.CurrentCommand))] {
				maybeRegisterWorker(cfg, role, wid)
				if err := launchWorker(cfg, role, wid, existing.PaneIndex); err != nil {
					return err
				}
			}
			continue
		}

		// For explicit add operations, always allocate a brand-new pane.
		pane, err := splitPane(cfg.Session)
		if err != nil {
			return err
		}
		if err := setPaneTitle(cfg.Session, pane.PaneIndex, wid); err != nil {
			return err
		}
		applyPaneProfileStyle(cfg.Session, pane.PaneIndex, wid)
		maybeRegisterWorker(cfg, role, wid)
		if err := launchWorker(cfg, role, wid, pane.PaneIndex); err != nil {
			return err
		}
	}

	_, err = runCommand("", "tmux", "select-layout", "-t", cfg.Session, "tiled")
	return err
}

func runDaemon(args []string) error {
	fs := flag.NewFlagSet("daemon", flag.ContinueOnError)
	configPath := fs.String("config", defaultConfigPath, "path to config")
	once := fs.Bool("once", false, "single run")
	poll := fs.Int("poll", 0, "override poll interval seconds")
	mode := fs.String("mode", "hybrid", "scheduler mode: tick|event|hybrid")
	fallback := fs.Int("fallback", 30, "fallback tick seconds in hybrid/event mode (0 disables)")
	sensor := fs.Int("sensor", 1, "change sensor interval seconds for event/hybrid")
	debounceMs := fs.Int("debounce-ms", 700, "debounce window for event triggers")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		return err
	}
	if err := validateConfig(cfg); err != nil {
		return err
	}
	if *poll > 0 {
		cfg.PollSeconds = *poll
	}
	if cfg.PollSeconds <= 0 {
		cfg.PollSeconds = 5
	}
	schedulerMode := strings.ToLower(strings.TrimSpace(*mode))
	if schedulerMode == "" {
		schedulerMode = "hybrid"
	}
	if schedulerMode != "tick" && schedulerMode != "event" && schedulerMode != "hybrid" {
		return fmt.Errorf("invalid --mode %q (expected tick|event|hybrid)", schedulerMode)
	}
	if *sensor <= 0 {
		*sensor = 1
	}
	if *debounceMs < 100 {
		*debounceMs = 100
	}
	debounceDur := time.Duration(*debounceMs) * time.Millisecond
	previousByWorker := map[string]WorkerStatus{}
	planReviewLaunched := false
	planReviewLastNudge := time.Time{}
	const planReviewRetryCooldown = 2 * time.Minute
	const planReviewStopGrace = 3 * time.Minute

	runCycle := func(trigger string) (bool, error) {
		if err := ensureSessionAndPanes(cfg); err != nil {
			return false, err
		}
		statuses, err := daemonCycle(cfg)
		if err != nil {
			return false, err
		}
		printDaemonCompactReport(trigger, statuses, previousByWorker)
		previousByWorker = snapshotStatusMap(statuses)
		if hasPrimaryBeadWork(cfg, statuses) {
			planReviewLaunched = false
			planReviewLastNudge = time.Time{}
			return false, nil
		}
		flow, _ := loadFlowSpec(cfg.ProjectRoot)
		if flowWantsPlanReviewer(flow) {
			shouldNudge := false
			if !planReviewLaunched {
				shouldNudge = true
			} else if !isPlanReviewerWorking(statuses) && !planReviewLastNudge.IsZero() && time.Since(planReviewLastNudge) >= planReviewRetryCooldown {
				shouldNudge = true
			}
			if shouldNudge {
				launched, err := maybeLaunchPlanReviewer(cfg)
				if err != nil {
					return false, err
				}
				if launched {
					planReviewLaunched = true
					planReviewLastNudge = time.Now()
					if shouldNudge && !planReviewLastNudge.IsZero() {
						fmt.Println("[daemon] no queue left; launched/re-nudged plan reviewer")
					}
					return false, nil
				}
			}
		}
		planReviewDone := planReviewLaunched && hasPlanReviewerCompletionSignal(statuses, planReviewLastNudge)
		if planReviewDone && flowWantsStopOnNoWork(flow) && !hasPrimaryBeadWork(cfg, statuses) {
			fmt.Println("[daemon] plan-review completed and no active bead work remains; stopping")
			return true, nil
		}
		if planReviewLaunched && flowWantsStopOnNoWork(flow) && !hasPrimaryBeadWork(cfg, statuses) && !isPlanReviewerWorking(statuses) && !planReviewLastNudge.IsZero() && time.Since(planReviewLastNudge) >= planReviewStopGrace {
			fmt.Println("[daemon] plan-review grace window elapsed with no active bead work; stopping")
			return true, nil
		}
		if shouldStopDaemonForNoWork(cfg, statuses) && flowWantsStopOnNoWork(flow) {
			fmt.Println("[daemon] no actionable work left (queue=0 assigned=0); stopping")
			return true, nil
		}
		return false, nil
	}

	stop, err := runCycle("start")
	if err != nil {
		return err
	}
	if stop {
		return nil
	}
	if *once {
		return nil
	}

	if schedulerMode == "tick" {
		ticker := time.NewTicker(time.Duration(cfg.PollSeconds) * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			stop, err := runCycle("tick")
			if err != nil {
				return err
			}
			if stop {
				return nil
			}
		}
	}

	sensorTicker := time.NewTicker(time.Duration(*sensor) * time.Second)
	defer sensorTicker.Stop()
	var fallbackTicker *time.Ticker
	if schedulerMode == "hybrid" || *fallback > 0 {
		if *fallback <= 0 {
			*fallback = max(20, cfg.PollSeconds)
		}
		fallbackTicker = time.NewTicker(time.Duration(*fallback) * time.Second)
		defer fallbackTicker.Stop()
	}

	lastFingerprint := computeEventFingerprint(cfg)
	var debounceTimer *time.Timer
	var debounceC <-chan time.Time
	eventPending := false
	resetDebounce := func() {
		if debounceTimer == nil {
			debounceTimer = time.NewTimer(debounceDur)
			debounceC = debounceTimer.C
			return
		}
		if !debounceTimer.Stop() {
			select {
			case <-debounceTimer.C:
			default:
			}
		}
		debounceTimer.Reset(debounceDur)
		debounceC = debounceTimer.C
	}
	clearDebounce := func() {
		if debounceTimer == nil {
			return
		}
		if !debounceTimer.Stop() {
			select {
			case <-debounceTimer.C:
			default:
			}
		}
		debounceC = nil
	}

	for {
		select {
		case <-sensorTicker.C:
			fp := computeEventFingerprint(cfg)
			if fp != lastFingerprint {
				lastFingerprint = fp
				eventPending = true
				resetDebounce()
			}
		case <-debounceC:
			if eventPending {
				stop, err := runCycle("event")
				if err != nil {
					return err
				}
				if stop {
					return nil
				}
				lastFingerprint = computeEventFingerprint(cfg)
				eventPending = false
			}
			clearDebounce()
		case <-func() <-chan time.Time {
			if fallbackTicker == nil {
				return nil
			}
			return fallbackTicker.C
		}():
			stop, err := runCycle("fallback-tick")
			if err != nil {
				return err
			}
			if stop {
				return nil
			}
			lastFingerprint = computeEventFingerprint(cfg)
		}
	}
}

func shouldStopDaemonForNoWork(cfg Config, statuses []WorkerStatus) bool {
	return !hasActionableWork(cfg, statuses)
}

func hasPrimaryBeadWork(cfg Config, statuses []WorkerStatus) bool {
	assigned := 0
	for _, s := range statuses {
		if strings.TrimSpace(s.BeadID) == "" {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(s.Role), "committer") {
			continue
		}
		assigned++
	}
	if assigned > 0 {
		return true
	}
	beads, err := listBeads(cfg.ProjectRoot)
	if err != nil {
		return true
	}
	queue := buildQueueByLabel(beads)
	return totalQueueCount(queue) > 0
}

func flowWantsPlanReviewer(flow FlowSpec) bool {
	for _, t := range flow.Transitions {
		if !strings.EqualFold(strings.TrimSpace(t.On), "condition:no_active_bead_work") {
			continue
		}
		for _, a := range t.Actions {
			if strings.EqualFold(strings.TrimSpace(a), "run_plan_reviewer") {
				return true
			}
		}
	}
	return false
}

func flowWantsStopOnNoWork(flow FlowSpec) bool {
	if len(flow.Transitions) == 0 {
		return true
	}
	for _, t := range flow.Transitions {
		if !strings.EqualFold(strings.TrimSpace(t.On), "condition:no_active_bead_work") {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(t.To), "plan.done") {
			return true
		}
		for _, a := range t.Actions {
			if strings.EqualFold(strings.TrimSpace(a), "stop_daemon") {
				return true
			}
		}
	}
	return false
}

func inferCurrentFlowNode(flow FlowSpec, stages WorkflowStageCounts, rows []WorkerStatus) string {
	if len(flow.States) == 0 {
		return ""
	}
	hasState := func(id string) bool {
		for _, st := range flow.States {
			if strings.EqualFold(strings.TrimSpace(st.ID), strings.TrimSpace(id)) {
				return true
			}
		}
		return false
	}
	if (stages.InImplementation+stages.QueueImpl+stages.AssignedImpl) > 0 && hasState("bead.implement") {
		return "bead.implement"
	}
	if (stages.InProof+stages.QueueProof+stages.AssignedProof) > 0 && hasState("bead.proof") {
		return "bead.proof"
	}
	if (stages.InReview+stages.QueueReview+stages.AssignedReview) > 0 && hasState("bead.review") {
		return "bead.review"
	}
	for _, r := range rows {
		if strings.EqualFold(strings.TrimSpace(r.Role), "plan-review") && !strings.EqualFold(strings.TrimSpace(r.State), "shell") {
			if hasState("plan.review") {
				return "plan.review"
			}
		}
	}
	if hasState("plan.done") {
		return "plan.done"
	}
	if strings.TrimSpace(flow.Start) != "" {
		return flow.Start
	}
	return ""
}

func renderFlowDAGLines(flow FlowSpec, current string, width int) []string {
	if len(flow.States) == 0 {
		return []string{reduce("(no .bsw/flow.{toml,yaml} states)", max(20, width-2))}
	}
	muted := lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	active := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("230")).Background(lipgloss.Color("62"))
	nodeStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("252"))
	nodeOrder := orderedFlowNodes(flow)
	transByFrom := map[string][]FlowTransition{}
	for _, tr := range flow.Transitions {
		k := strings.TrimSpace(tr.From)
		transByFrom[k] = append(transByFrom[k], tr)
	}
	stateByID := map[string]FlowState{}
	for _, st := range flow.States {
		stateByID[strings.TrimSpace(st.ID)] = st
	}

	lines := make([]string, 0, len(nodeOrder)+len(flow.Transitions)+8)
	lines = append(lines, muted.Render("main lane (horizontal):"))
	mainLane := make([]string, 0, len(nodeOrder))
	for _, id := range nodeOrder {
		st := stateByID[id]
		label := compactFlowNodeLabel(id, st.Kind)
		box := "[" + label + "]"
		if strings.EqualFold(strings.TrimSpace(id), strings.TrimSpace(current)) {
			box = active.Render(" " + box + " ")
		} else {
			box = nodeStyle.Render(box)
		}
		mainLane = append(mainLane, box)
	}
	lane := strings.Join(mainLane, muted.Render(" -> "))
	lines = append(lines, reduce(lane, max(20, width-2)))

	lines = append(lines, "")
	lines = append(lines, muted.Render("edges:"))
	for i, tr := range flow.Transitions {
		from := compactFlowID(tr.From)
		to := compactFlowID(tr.To)
		on := strings.TrimSpace(tr.On)
		if on == "" {
			on = "-"
		}
		edge := fmt.Sprintf("%2d. %s ──[%s]──▶ %s", i+1, from, on, to)
		if strings.TrimSpace(tr.Guard) != "" {
			edge += "  guard:" + strings.TrimSpace(tr.Guard)
		}
		if len(tr.Actions) > 0 {
			edge += "  actions:[" + strings.Join(tr.Actions, ", ") + "]"
		}
		lines = append(lines, muted.Render(reduce(edge, max(20, width-2))))
	}
	return lines
}

func compactFlowID(id string) string {
	id = strings.TrimSpace(id)
	id = strings.TrimPrefix(id, "bead.")
	id = strings.TrimPrefix(id, "plan.")
	return id
}

func compactFlowNodeLabel(id, kind string) string {
	k := strings.TrimSpace(kind)
	if k == "" {
		k = "-"
	}
	return compactFlowID(id) + " [" + k + "]"
}

func orderedFlowNodes(flow FlowSpec) []string {
	seen := map[string]bool{}
	out := []string{}
	push := func(id string) {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			return
		}
		seen[id] = true
		out = append(out, id)
	}
	push(flow.Start)
	for _, tr := range flow.Transitions {
		push(tr.From)
		push(tr.To)
	}
	for _, st := range flow.States {
		push(st.ID)
	}
	return out
}

func isPlanReviewerWorking(statuses []WorkerStatus) bool {
	for _, s := range statuses {
		if !strings.EqualFold(strings.TrimSpace(s.Role), "plan-review") {
			continue
		}
		st := strings.ToLower(strings.TrimSpace(s.State))
		if st == "busy" || st == "assigned" {
			return true
		}
	}
	return false
}

func hasPlanReviewerCompletionSignal(statuses []WorkerStatus, lastNudge time.Time) bool {
	if lastNudge.IsZero() {
		return false
	}
	sinceNudge := time.Since(lastNudge)
	slack := 8 * time.Second
	for _, s := range statuses {
		if !strings.EqualFold(strings.TrimSpace(s.Role), "plan-review") {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(s.Reason), "beacon-plan-review-done") || strings.EqualFold(strings.TrimSpace(s.Reason), "pane-state-plan-done") {
			return true
		}
		st := strings.ToLower(strings.TrimSpace(s.State))
		if st == "busy" || st == "assigned" {
			return false
		}
		if hasPlanDoneMarkerInPane(s.Session, s.Pane) {
			return true
		}
		// Activity/transcript touched after last nudge => run likely executed.
		if s.ActivityAge > 0 && s.ActivityAge <= sinceNudge+slack {
			return true
		}
		if s.TranscriptAge > 0 && s.TranscriptAge <= sinceNudge+slack {
			return true
		}
	}
	return false
}

func hasPlanDoneMarkerInPane(session string, pane int) bool {
	out, err := runCommand("", "tmux", "capture-pane", "-p", "-t", fmt.Sprintf("%s.%d", session, pane), "-S", "-100")
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(out), "state plan:done") || strings.Contains(strings.ToLower(out), "state: plan:done")
}

func hasPendingCommitQueue(projectRoot string) bool {
	q, err := loadCommitQueue(projectRoot)
	if err != nil {
		return false
	}
	return len(q.Pending) > 0
}

func hasActionableWork(cfg Config, statuses []WorkerStatus) bool {
	assigned := 0
	for _, s := range statuses {
		if strings.TrimSpace(s.BeadID) == "" {
			continue
		}
		role := strings.ToLower(strings.TrimSpace(s.Role))
		if role == "committer" || role == "plan-review" {
			continue
		}
		assigned++
	}
	if assigned > 0 {
		return true
	}
	beads, err := listBeads(cfg.ProjectRoot)
	if err != nil {
		return true
	}
	queue := buildQueueByLabel(beads)
	if totalQueueCount(queue) > 0 {
		return true
	}
	return hasPendingCommitQueue(cfg.ProjectRoot)
}

func maybeLaunchPlanReviewer(cfg Config) (bool, error) {
	if !cfg.PlanReview.Enabled {
		return false, nil
	}
	flow, _ := loadFlowSpec(cfg.ProjectRoot)
	planState := findFlowStateByID(flow, "plan.review")
	role := RoleConfig{
		Name:          "plan-review",
		Label:         "plan-review",
		Workers:       1,
		Provider:      firstNonEmpty(planState.Provider, cfg.PlanReview.Provider, "cc"),
		Model:         firstNonEmpty(planState.Model, cfg.PlanReview.Model),
		Effort:        firstNonEmpty(planState.Effort, cfg.PlanReview.Effort),
		PromptFile:    firstNonEmpty(planState.Prompt, cfg.PlanReview.PromptFile),
		LaunchCommand: cfg.PlanReview.LaunchCommand,
	}
	workerID := cfg.Session + ":plan-review:01"
	if panes, err := listPanes(cfg.Session, false); err == nil {
		for _, p := range panes {
			if strings.TrimSpace(p.PaneTitle) == workerID {
				applyPaneProfileStyle(cfg.Session, p.PaneIndex, workerID)
				if shellCommands[strings.ToLower(strings.TrimSpace(p.CurrentCommand))] {
					maybeRegisterWorker(cfg, role, workerID)
					if err := launchWorker(cfg, role, workerID, p.PaneIndex); err != nil {
						return false, err
					}
					time.Sleep(1200 * time.Millisecond)
				}
				if err := sendAgentPrompt(cfg.Session, p.PaneIndex, planReviewMessage(cfg)); err != nil {
					return false, err
				}
				return true, nil
			}
		}
	}
	pane, err := splitPane(cfg.Session)
	if err != nil {
		return false, err
	}
	if err := setPaneTitle(cfg.Session, pane.PaneIndex, workerID); err != nil {
		return false, err
	}
	applyPaneProfileStyle(cfg.Session, pane.PaneIndex, workerID)
	maybeRegisterWorker(cfg, role, workerID)
	if err := launchWorker(cfg, role, workerID, pane.PaneIndex); err != nil {
		return false, err
	}
	time.Sleep(1200 * time.Millisecond)
	if err := sendAgentPrompt(cfg.Session, pane.PaneIndex, planReviewMessage(cfg)); err != nil {
		return false, err
	}
	_, _ = runCommand("", "tmux", "select-layout", "-t", cfg.Session, "tiled")
	return true, nil
}

func findFlowStateByID(flow FlowSpec, id string) FlowState {
	for _, st := range flow.States {
		if strings.EqualFold(strings.TrimSpace(st.ID), strings.TrimSpace(id)) {
			return st
		}
	}
	return FlowState{}
}

func planReviewMessage(cfg Config) string {
	var b strings.Builder
	fmt.Fprintf(&b, "PLAN_REVIEW project=%s\n", cfg.ProjectRoot)
	fmt.Fprintf(&b, "Goal: review current execution plan and recreate/reopen missing beads if more work is needed.\n")
	fmt.Fprintf(&b, "Use the workflow prompt and produce concrete bead actions using br.\n")
	fmt.Fprintf(&b, "Runtime Protocol (mandatory):\n")
	fmt.Fprintf(&b, "- First emit: SWARM_STATUS role=plan-review state=WORKING\n")
	fmt.Fprintf(&b, "- On completion emit BOTH lines:\n")
	fmt.Fprintf(&b, "  STATE plan:done\n")
	fmt.Fprintf(&b, "  SWARM_STATUS role=plan-review state=WAITING reason=plan_review_done\n")
	fmt.Fprintf(&b, "- Do not omit beacon/state lines even when no changes are needed.\n")
	fmt.Fprintf(&b, "Rules:\n")
	fmt.Fprintf(&b, "- Create actionable beads with needs-impl label.\n")
	fmt.Fprintf(&b, "- If work is already complete, do not create duplicate beads.\n")
	fmt.Fprintf(&b, "- If reopening is needed, update existing beads instead of cloning duplicates.\n")
	fmt.Fprintf(&b, "- Summarize what you created/updated in a final bead comment.\n")
	meta, _ := loadSwarmMeta(cfg.ProjectRoot)
	if strings.TrimSpace(meta.PlanFile) != "" {
		planPath := expandHome(meta.PlanFile)
		fmt.Fprintf(&b, "PLAN_FILE: %s\n", planPath)
		if text := readFileBestEffort(planPath); text != "" {
			fmt.Fprintf(&b, "PLAN_CONTENT:\n%s\n", trimTo(text, 12000))
		}
	}
	if len(meta.Topics) > 0 {
		fmt.Fprintf(&b, "TOPICS: %s\n", strings.Join(meta.Topics, ", "))
	}
	return b.String()
}

func loadSwarmMeta(projectRoot string) (SwarmMeta, error) {
	path := filepath.Join(projectRoot, defaultMetaPath)
	buf, err := os.ReadFile(path)
	if err != nil {
		return SwarmMeta{}, err
	}
	var meta SwarmMeta
	sc := bufio.NewScanner(bytes.NewReader(buf))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "plan_file") {
			if v, ok := parseTomlKV(line); ok {
				meta.PlanFile = v
			}
			continue
		}
		if strings.HasPrefix(line, "topics") {
			if idx := strings.Index(line, "="); idx >= 0 {
				meta.Topics = parseTomlArray(line[idx+1:])
			}
		}
	}
	return meta, nil
}

func writeSwarmMeta(path string, meta SwarmMeta) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString("# bsw swarm metadata\n")
	b.WriteString("plan_file = " + strconv.Quote(strings.TrimSpace(meta.PlanFile)) + "\n")
	b.WriteString("topics = [")
	for i, t := range meta.Topics {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(strconv.Quote(strings.TrimSpace(t)))
	}
	b.WriteString("]\n")
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func parseTomlKV(line string) (string, bool) {
	idx := strings.Index(line, "=")
	if idx < 0 {
		return "", false
	}
	raw := strings.TrimSpace(line[idx+1:])
	if raw == "" {
		return "", true
	}
	if strings.HasPrefix(raw, `"`) {
		if unq, err := strconv.Unquote(raw); err == nil {
			return strings.TrimSpace(unq), true
		}
	}
	return strings.Trim(strings.TrimSpace(raw), `"'`), true
}

func parseTomlArray(raw string) []string {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]") {
		raw = strings.TrimSpace(raw[1 : len(raw)-1])
	}
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.HasPrefix(p, `"`) {
			if unq, err := strconv.Unquote(p); err == nil {
				p = unq
			}
		}
		p = strings.Trim(strings.TrimSpace(p), `"'`)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

const defaultFlowTOML = `version = 1
start = "bead.implement"

[[states]]
id = "bead.implement"
kind = "bead"
label = "needs-impl"
workers = 4
prompt = ".bsw/prompts/impl_worker.md"
provider = "codex"
model = "gpt-5.3-codex"
effort = "medium"
max_idle = "20m"
max_lifetime = "3h"
max_busy_without_progress = "30m"
respawn = "true"
color_bg = "#1e3a8a"
color_fg = "#f8fbff"
tmux_bg = "colour33"
tmux_fg = "colour255"

[[states]]
id = "bead.proof"
kind = "bead"
label = "needs-proof"
workers = 2
prompt = ".bsw/prompts/impl_proofer.md"
provider = "cc"
model = "opus"
effort = "high"
max_idle = "15m"
max_lifetime = "2h"
max_busy_without_progress = "25m"
respawn = "true"
color_bg = "#92400e"
color_fg = "#fff8f2"
tmux_bg = "colour94"
tmux_fg = "colour255"

[[states]]
id = "bead.review"
kind = "bead"
label = "needs-review"
workers = 2
prompt = ".bsw/prompts/impl_reviewer.md"
provider = "cc"
model = "opus"
effort = "high"
max_idle = "15m"
max_lifetime = "2h"
max_busy_without_progress = "25m"
respawn = "true"
color_bg = "#166534"
color_fg = "#f3fff7"
tmux_bg = "colour28"
tmux_fg = "colour255"

[[states]]
id = "worker.committer"
kind = "worker"
label = "commit-queue"
workers = 1
prompt = ".bsw/prompts/impl_committer.md"
provider = "cc"
model = "opus"
effort = "medium"
max_idle = "10m"
max_lifetime = "90m"
max_busy_without_progress = "20m"
one_shot = "true"
respawn = "true"
color_bg = "#7c3aed"
color_fg = "#f8f3ff"
tmux_bg = "colour56"
tmux_fg = "colour255"

[[states]]
id = "plan.review"
kind = "plan"
label = "plan-review"
workers = 1
prompt = ".bsw/prompts/plan_reviewer.md"
provider = "cc"
model = "opus"
effort = "high"
max_idle = "10m"
max_lifetime = "90m"
max_busy_without_progress = "20m"
one_shot = "true"
respawn = "true"
color_bg = "#be123c"
color_fg = "#fff1f2"
tmux_bg = "colour161"
tmux_fg = "colour255"

[[states]]
id = "plan.done"
kind = "terminal"

[[transitions]]
from = "bead.implement"
on = "state:impl:done"
to = "bead.proof"
actions = ["clear_assignee", "set_label:needs-proof", "remove_label:needs-impl"]

[[transitions]]
from = "bead.proof"
on = "state:proof:passed"
to = "bead.review"
actions = ["clear_assignee", "set_label:needs-review", "remove_label:needs-proof"]

[[transitions]]
from = "bead.proof"
on = "state:proof:failed"
to = "bead.implement"
actions = ["clear_assignee", "set_label:needs-impl", "remove_label:needs-proof"]

[[transitions]]
from = "bead.review"
on = "state:review:failed"
to = "bead.implement"
actions = ["clear_assignee", "set_label:needs-impl", "remove_label:needs-review"]

[[transitions]]
from = "bead.review"
on = "state:review:passed"
to = "plan.review"
actions = ["clear_assignee", "remove_label:needs-review", "close_bead"]

[[transitions]]
from = "plan.review"
on = "condition:no_active_bead_work"
guard = "run_plan_reviewer_once"
to = "plan.review"
actions = ["run_plan_reviewer"]

[[transitions]]
from = "plan.review"
on = "condition:no_active_bead_work"
to = "plan.done"
actions = ["set_plan_state:done", "stop_daemon"]
`

var defaultPromptFiles = map[string]string{
	"impl_worker.md": `# Implement Worker

## Pre-Checklist
1. Read AGENTS.md.
2. Pull and inspect the assigned bead.
3. Confirm scope and acceptance criteria.

## Main Task
1. Implement only the assigned bead.
2. Keep changes minimal and coherent.
3. If blocked, report blocker + unblocking action.

## Post-Checklist
1. Add bead comment with results and evidence paths.
2. Emit SWARM_STATUS and wait for next instruction.
`,
	"impl_proofer.md": `# Proof Worker

## Pre-Checklist
1. Read AGENTS.md.
2. Pull and inspect the assigned bead.
3. Verify gate commands and evidence context.

## Main Task
1. Run required proof/gate commands.
2. Record exact commands and outputs.
3. Do not implement code changes.

## Post-Checklist
1. Add bead comment with PASS/FAIL and evidence.
2. Emit SWARM_STATUS and wait for next instruction.
`,
	"impl_reviewer.md": `# Review Worker

## Pre-Checklist
1. Read AGENTS.md.
2. Pull and inspect the assigned bead.
3. Load implementation and proof evidence.

## Main Task
1. Review correctness, scope, and acceptance criteria.
2. Request changes with concrete file-level guidance when needed.
3. Do not commit.

## Post-Checklist
1. Add bead comment with review decision and rationale.
2. Emit SWARM_STATUS and wait for next instruction.
`,
	"impl_committer.md": `# Committer Worker

## Pre-Checklist
1. Read AGENTS.md.
2. Verify commit trigger context from orchestrator.

## Main Task
1. Commit and push current logical changes only.
2. Use explicit commit messages.
3. If no changes exist, report waiting.

## Post-Checklist
1. Emit SWARM_STATUS reason=cycle_complete or reason=no_changes.
2. Return to waiting.
`,
	"plan_reviewer.md": `# Plan Reviewer

## Pre-Checklist
1. Read AGENTS.md.
2. Load PLAN_FILE and active implementation pointers.

## Main Task
1. Build a checklist from the plan.
2. Mark done vs missing with evidence.
3. Run relevant gates/smoke checks.

## Post-Checklist
1. PASS: move plan to completed.
2. FAIL: create follow-up beads for missing work.
3. Emit SWARM_STATUS and wait.
`,
}

func writeDefaultPromptSet(promptsRoot string) error {
	if err := os.MkdirAll(promptsRoot, 0o755); err != nil {
		return err
	}
	for name, content := range defaultPromptFiles {
		path := filepath.Join(promptsRoot, name)
		if _, err := os.Stat(path); err == nil {
			continue
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func writeDefaultFlowTOML(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(defaultFlowTOML), 0o644)
}

func effectiveFlowPath(projectRoot string) string {
	candidates := []string{
		filepath.Join(projectRoot, defaultFlowPath),
		filepath.Join(projectRoot, legacyFlowPathYAML),
		filepath.Join(projectRoot, legacyFlowPathYML),
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return candidates[0]
}

func loadFlowSpec(projectRoot string) (FlowSpec, error) {
	type flowDoc struct {
		Version     int              `toml:"version" yaml:"version"`
		Start       string           `toml:"start" yaml:"start"`
		States      []FlowState      `toml:"states" yaml:"states"`
		Transitions []FlowTransition `toml:"transitions" yaml:"transitions"`
	}
	candidates := []struct {
		path   string
		format string
	}{
		{path: filepath.Join(projectRoot, defaultFlowPath), format: "toml"},
		{path: filepath.Join(projectRoot, legacyFlowPathYAML), format: "yaml"},
		{path: filepath.Join(projectRoot, legacyFlowPathYML), format: "yaml"},
	}
	var firstErr error
	for _, c := range candidates {
		buf, err := os.ReadFile(c.path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		var doc flowDoc
		switch c.format {
		case "yaml":
			err = yaml.Unmarshal(buf, &doc)
		default:
			err = toml.Unmarshal(buf, &doc)
		}
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("%s parse failed: %w", c.path, err)
			}
			continue
		}
		flow := FlowSpec{
			Version:     doc.Version,
			Start:       strings.TrimSpace(doc.Start),
			States:      doc.States,
			Transitions: doc.Transitions,
		}
		return flow, nil
	}
	if firstErr != nil {
		return FlowSpec{}, firstErr
	}
	return FlowSpec{}, os.ErrNotExist
}

func runTick(args []string) error {
	fs := flag.NewFlagSet("tick", flag.ContinueOnError)
	configPath := fs.String("config", defaultConfigPath, "path to config")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		return err
	}
	if err := validateConfig(cfg); err != nil {
		return err
	}

	if err := ensureSessionAndPanes(cfg); err != nil {
		return err
	}

	beforeRows, err := collectStatuses(cfg, false)
	if err != nil {
		return err
	}
	beforeBeads, err := listBeads(cfg.ProjectRoot)
	if err != nil {
		return err
	}
	beforeQueue := buildQueueByLabel(beforeBeads)

	afterRows, err := daemonCycle(cfg)
	if err != nil {
		return err
	}
	flow, _ := loadFlowSpec(cfg.ProjectRoot)
	if !hasPrimaryBeadWork(cfg, afterRows) && flowWantsPlanReviewer(flow) {
		launched, err := maybeLaunchPlanReviewer(cfg)
		if err != nil {
			return fmt.Errorf("plan-review launch failed: %w", err)
		}
		if launched {
			afterRows, _ = collectStatuses(cfg, false)
		}
	}
	afterBeads, err := listBeads(cfg.ProjectRoot)
	if err != nil {
		return err
	}
	afterQueue := buildQueueByLabel(afterBeads)

	printTickReport(cfg, beforeRows, afterRows, beforeBeads, afterBeads, beforeQueue, afterQueue)
	return nil
}

func runStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	configPath := fs.String("config", defaultConfigPath, "path to config")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		return err
	}
	if err := validateConfig(cfg); err != nil {
		return err
	}

	rows, err := collectStatuses(cfg, true)
	if err != nil {
		return err
	}
	printStatusTable(rows)
	return nil
}

func runZoom(args []string) error {
	fs := flag.NewFlagSet("zoom", flag.ContinueOnError)
	session := fs.String("session", "", "tmux session")
	pane := fs.Int("pane", -1, "pane index")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *session == "" || *pane < 0 {
		return errors.New("zoom requires --session and --pane")
	}
	return zoomPane(*session, *pane)
}

func runTUI(args []string) error {
	fs := flag.NewFlagSet("tui", flag.ContinueOnError)
	configPath := fs.String("config", defaultConfigPath, "path to config")
	refresh := fs.Int("refresh", 1, "refresh interval seconds")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		return err
	}
	if err := validateConfig(cfg); err != nil {
		return err
	}
	if *refresh <= 0 {
		*refresh = 1
	}

	model := newTUIModel(cfg, time.Duration(*refresh)*time.Second)
	p := tea.NewProgram(model, tea.WithAltScreen())
	finalModel, err := p.Run()
	if err != nil {
		return err
	}
	m := finalModel.(tuiModel)
	if m.zoomTarget != nil {
		return zoomPane(m.zoomTarget.Session, m.zoomTarget.Pane)
	}
	return nil
}

func daemonCycle(cfg Config) ([]WorkerStatus, error) {
	beads, err := listBeads(cfg.ProjectRoot)
	if err != nil {
		return nil, err
	}
	dedupChanged, err := dedupeWorkerAssignees(cfg, beads)
	if err != nil {
		return nil, err
	}
	if dedupChanged > 0 {
		beads, err = listBeads(cfg.ProjectRoot)
		if err != nil {
			return nil, err
		}
	}
	changed, err := reconcileBeadTransitions(cfg, beads)
	if err != nil {
		return nil, err
	}
	if changed > 0 {
		beads, err = listBeads(cfg.ProjectRoot)
		if err != nil {
			return nil, err
		}
	}
	closedRoots, err := autoCloseDormantRootBeads(cfg)
	if err != nil {
		return nil, err
	}
	if closedRoots > 0 {
		beads, err = listBeads(cfg.ProjectRoot)
		if err != nil {
			return nil, err
		}
	}
	latestState, _ := readLatestStateByBead(cfg.ProjectRoot)
	commitQ, _ := loadCommitQueue(cfg.ProjectRoot)
	commitChanged := reconcileCommitQueue(latestState, &commitQ)

	statuses, err := collectStatuses(cfg, false)
	if err != nil {
		return nil, err
	}

	queueByLabel := buildQueueByLabel(beads)
	roleMap := mapRoleConfig(cfg.Roles)
	beadByID := make(map[string]Bead, len(beads))
	for _, b := range beads {
		beadByID[b.ID] = b
	}
	runtimeMap, _ := loadWorkerRuntimeMap(cfg.ProjectRoot)
	runtimeDirty := false
	now := time.Now().UTC()

	for i := range statuses {
		s := &statuses[i]
		if strings.EqualFold(s.Role, "committer") {
			roleCfg, ok := roleMap[s.Role]
			if !ok {
				continue
			}
			rt := runtimeMap[s.WorkerID]
			current := strings.TrimSpace(rt.CommitBeadID)
			if current != "" {
				st := strings.ToLower(strings.TrimSpace(latestState[current]))
				if st == "commit:done" || st == "commit:failed" {
					rt.CommitBeadID = ""
					rt.CommitStartedAt = ""
					runtimeMap[s.WorkerID] = rt
					runtimeDirty = true
					if removeCommitJob(&commitQ, current) {
						commitChanged = true
					}
					s.BeadID = ""
					s.BeadTitle = ""
					s.State = "idle"
					s.Reason = "commit-finished"
					continue
				}
				s.BeadID = current
				s.State = "busy"
				s.Reason = "commit-in-progress"
				continue
			}
			job, ok := firstCommitJob(commitQ)
			if !ok {
				s.State = "idle"
				s.Reason = "commit-queue-empty"
				continue
			}
			msg := committerAssignmentMessage(*s, job.BeadID, roleCfg)
			if err := sendAgentPrompt(s.Session, s.Pane, msg); err != nil {
				s.State = "error"
				s.Reason = err.Error()
				continue
			}
			rt.CommitBeadID = job.BeadID
			rt.CommitStartedAt = now.Format(time.RFC3339Nano)
			runtimeMap[s.WorkerID] = rt
			runtimeDirty = true
			s.BeadID = job.BeadID
			s.State = "assigned"
			s.Reason = "commit-assigned"
			s.Activity = "assigned"
			continue
		}
		// Only skip workers that are truly unavailable:
		// - shell: agent CLI is not running
		// - already assigned: bead is actively owned by this worker
		if s.State == "shell" {
			continue
		}
		if strings.TrimSpace(s.BeadID) != "" {
			roleCfg, roleOK := roleMap[s.Role]
			bead := beadByID[s.BeadID]
			// Keep auto-release for implement only. Proof/review can appear transcript-idle
			// while still processing, which causes assignment ping-pong.
			if strings.EqualFold(strings.TrimSpace(s.Role), "implement") && shouldReleaseStuckAssignment(cfg, *s, bead) {
				if _, err := runCommand(cfg.ProjectRoot, "br", "update", s.BeadID, "--assignee", "", "--actor", cfg.Actor); err == nil {
					if roleOK && bead.ID != "" {
						queueByLabel[roleCfg.Label] = append(queueByLabel[roleCfg.Label], bead)
					}
					rt := runtimeMap[s.WorkerID]
					rt.LastReleasedAt = now.Format(time.RFC3339Nano)
					rt.LastReleasedBead = s.BeadID
					runtimeMap[s.WorkerID] = rt
					runtimeDirty = true
					s.BeadID = ""
					s.BeadTitle = ""
					s.Label = ""
					s.State = "idle"
					s.Reason = "released-stuck-assignment"
					s.Activity = "released"
				}
				continue
			}
			// Assigned but waiting workers get periodic nudges so ticks do useful work.
			if s.State == "waiting" {
				if roleOK {
					rt := runtimeMap[s.WorkerID]
					if shouldNudgeAssignedWorker(rt, now, 3*time.Minute) && strings.TrimSpace(rt.LastNudgeBead) != strings.TrimSpace(s.BeadID) {
						if bead.ID == "" {
							bead = Bead{ID: s.BeadID, Title: s.BeadTitle}
						}
						msg := nudgeMessage(*s, bead, roleCfg)
						if err := sendAgentPrompt(s.Session, s.Pane, msg); err == nil {
							rt.LastNudgeAt = now.Format(time.RFC3339Nano)
							rt.LastNudgeBead = s.BeadID
							runtimeMap[s.WorkerID] = rt
							runtimeDirty = true
							s.Reason = "nudge-sent"
							s.Activity = "nudged"
						}
					}
				}
			}
			continue
		}

		roleCfg, ok := roleMap[s.Role]
		if !ok {
			continue
		}
		queue := queueByLabel[roleCfg.Label]
		rt := runtimeMap[s.WorkerID]
		candidate, remaining := pickAssignableBeadForWorker(rt, queue, now, 10*time.Minute)
		queueByLabel[roleCfg.Label] = remaining
		if candidate.ID == "" {
			s.State = "idle"
			s.Reason = "queue-empty"
			continue
		}

		if err := assignBead(cfg, candidate, s.WorkerID); err != nil {
			s.State = "error"
			s.Reason = err.Error()
			continue
		}

		msg := assignmentMessage(*s, candidate, roleCfg)
		if err := sendAgentPrompt(s.Session, s.Pane, msg); err != nil {
			s.State = "error"
			s.Reason = err.Error()
			continue
		}

		s.State = "assigned"
		s.BeadID = candidate.ID
		s.BeadTitle = candidate.Title
		s.Label = roleCfg.Label
		s.Activity = "assigned"
		s.Reason = "assigned"
	}
	if runtimeDirty {
		_ = saveWorkerRuntimeMap(cfg.ProjectRoot, runtimeMap)
	}
	if commitChanged {
		_ = saveCommitQueue(cfg.ProjectRoot, commitQ)
	}

	// Reap workers via lifecycle policy from flow.toml.
	flow, _ := loadFlowSpec(cfg.ProjectRoot)
	policies := flowLifecyclePolicies(flow)
	reaped := false
	for _, s := range statuses {
		policy, hasPolicy := policies[s.Role]
		idleAge := workerIdleAge(s)
		stLower := strings.ToLower(strings.TrimSpace(s.State))

		// Recycle old panes regardless of queue to avoid stale long-lived sessions.
		if hasPolicy && policy.MaxLifetime > 0 && s.Duration > policy.MaxLifetime {
			if strings.TrimSpace(s.BeadID) != "" {
				if bead, ok := beadByID[s.BeadID]; ok {
					_ = applyTransitionUpdate(cfg, bead, firstNeedsLabel(bead.Labels), false)
				}
			}
			target := fmt.Sprintf("%s.%d", s.Session, s.Pane)
			if _, err := runCommand("", "tmux", "kill-pane", "-t", target); err == nil {
				reaped = true
			}
			continue
		}

		// Busy without progress watchdog: recycle and unassign so queue can continue.
		if hasPolicy && strings.TrimSpace(s.BeadID) != "" && policy.MaxBusyWithoutProgress > 0 && idleAge > policy.MaxBusyWithoutProgress {
			if bead, ok := beadByID[s.BeadID]; ok {
				_ = applyTransitionUpdate(cfg, bead, firstNeedsLabel(bead.Labels), false)
			}
			target := fmt.Sprintf("%s.%d", s.Session, s.Pane)
			if _, err := runCommand("", "tmux", "kill-pane", "-t", target); err == nil {
				reaped = true
			}
			continue
		}

		// Idle/waiting ready panes may be retired even before queue-empty check.
		if hasPolicy && strings.TrimSpace(s.BeadID) == "" && policy.MaxIdle > 0 &&
			(stLower == "idle" || stLower == "waiting" || stLower == "ready") &&
			idleAge > policy.MaxIdle {
			target := fmt.Sprintf("%s.%d", s.Session, s.Pane)
			if _, err := runCommand("", "tmux", "kill-pane", "-t", target); err == nil {
				reaped = true
			}
			continue
		}

		// One-shot workers are retired immediately when unassigned and not busy.
		if hasPolicy && policy.OneShot && strings.TrimSpace(s.BeadID) == "" && stLower != "busy" {
			target := fmt.Sprintf("%s.%d", s.Session, s.Pane)
			if _, err := runCommand("", "tmux", "kill-pane", "-t", target); err == nil {
				reaped = true
			}
			continue
		}

		// Reap idle/waiting workers when their role has no queue work.
		// Keep primary lanes warm; only retire async/ephemeral roles.
		if strings.TrimSpace(s.BeadID) != "" {
			continue
		}
		if stLower != "idle" && stLower != "waiting" && stLower != "ready" {
			continue
		}
		roleName := strings.ToLower(strings.TrimSpace(s.Role))
		if roleName != "committer" && roleName != "plan-review" {
			continue
		}
		noWork := false
		if strings.EqualFold(strings.TrimSpace(s.Role), "committer") {
			noWork = len(commitQ.Pending) == 0
		} else if rc, ok := roleMap[s.Role]; ok {
			noWork = len(queueByLabel[rc.Label]) == 0
		}
		if !noWork {
			continue
		}
		target := fmt.Sprintf("%s.%d", s.Session, s.Pane)
		if _, err := runCommand("", "tmux", "kill-pane", "-t", target); err == nil {
			reaped = true
		}
	}
	if reaped {
		refreshed, err := collectStatuses(cfg, false)
		if err == nil {
			return refreshed, nil
		}
	}

	return statuses, nil
}

func dedupeWorkerAssignees(cfg Config, beads []Bead) (int, error) {
	byAssignee := map[string][]Bead{}
	for _, b := range beads {
		a := strings.TrimSpace(b.Assignee)
		if a == "" {
			continue
		}
		byAssignee[a] = append(byAssignee[a], b)
	}
	changed := 0
	for assignee, items := range byAssignee {
		if len(items) <= 1 {
			continue
		}
		sort.Slice(items, func(i, j int) bool {
			ti := parseRuntimeTime(items[i].UpdatedAt)
			tj := parseRuntimeTime(items[j].UpdatedAt)
			if !ti.Equal(tj) {
				return ti.After(tj)
			}
			return items[i].ID < items[j].ID
		})
		keep := items[0].ID
		for _, b := range items[1:] {
			_, err := runCommand(cfg.ProjectRoot, "br", "update", b.ID, "--assignee", "", "--actor", cfg.Actor)
			if err != nil {
				return changed, err
			}
			changed++
		}
		fmt.Fprintf(os.Stderr, "warning: deduped assignee %s; kept %s released %d\n", assignee, keep, len(items)-1)
	}
	return changed, nil
}

func collectStatuses(cfg Config, allSessions bool) ([]WorkerStatus, error) {
	panes, err := listPanes(cfg.Session, allSessions)
	if err != nil {
		return nil, err
	}

	beads, err := listBeads(cfg.ProjectRoot)
	if err != nil {
		return nil, err
	}

	beadByAssignee := map[string]Bead{}
	for _, b := range beads {
		if strings.TrimSpace(b.Assignee) != "" {
			beadByAssignee[b.Assignee] = b
		}
	}

	roleMap := mapRoleConfig(cfg.Roles)
	tokenCache := map[string]tokenSnapshot{}
	runtimeMap, _ := loadWorkerRuntimeMap(cfg.ProjectRoot)
	runtimeDirty := false
	usedTranscriptPaths := map[string]bool{}
	for _, rt := range runtimeMap {
		if p := strings.TrimSpace(rt.TranscriptPath); p != "" {
			usedTranscriptPaths[expandHome(p)] = true
		}
	}

	rows := make([]WorkerStatus, 0, len(panes))
	for _, p := range panes {
		w, ok := parseWorkerTitle(p.PaneTitle)
		if !ok {
			continue
		}
		if !allSessions && w.Session != cfg.Session {
			continue
		}

		st := WorkerStatus{
			Session:     p.Session,
			WorkerID:    p.PaneTitle,
			AgentName:   deterministicAgentName(p.PaneTitle),
			Role:        w.Role,
			Pane:        p.PaneIndex,
			State:       "idle",
			StartedAt:   p.StartAt,
			Duration:    sinceSafe(p.StartAt),
			ActivityAge: sinceSafe(p.ActivityAt),
			Provider:    normalizeProvider(p.CurrentCommand),
			Model:       "-",
			Effort:      "-",
		}
		if st.StartedAt.IsZero() {
			if rt, ok := runtimeMap[st.WorkerID]; ok {
				if launched := parseWorkerLaunchTime(rt); !launched.IsZero() {
					st.StartedAt = launched
					st.Duration = sinceSafe(launched)
				}
			}
		}

		roleCfg, roleOk := roleMap[st.Role]
		if roleOk {
			if roleCfg.Provider != "" {
				st.Provider = roleCfg.Provider
			}
			if roleCfg.Model != "" {
				st.Model = roleCfg.Model
			}
			if roleCfg.Effort != "" {
				st.Effort = roleCfg.Effort
			}
		}

		if shellCommands[strings.ToLower(p.CurrentCommand)] {
			st.State = "shell"
			st.Reason = "agent-not-running"
		} else if bead, ok := beadByAssignee[st.WorkerID]; ok {
			st.State = "busy"
			st.BeadID = bead.ID
			st.BeadTitle = bead.Title
			st.Label = firstNeedsLabel(bead.Labels)
			st.Reason = "bead-assignee"
		} else {
			st.State = "ready"
			st.Reason = "no-assignee"
		}

		var latestBeacon SwarmBeacon
		var hasBeacon bool
		if roleOk && strings.TrimSpace(roleCfg.TranscriptGlob) != "" {
			rt := runtimeMap[st.WorkerID]
			provider := normalizeProvider(firstNonEmpty(roleCfg.Provider, st.Provider))
			sessionID := strings.TrimSpace(rt.SessionID)
			transcriptPath := strings.TrimSpace(rt.TranscriptPath)
			launchedAt := parseWorkerLaunchTime(rt)

			if provider == "cc" {
				if sessionID != "" && transcriptPath == "" {
					transcriptPath = claudeWorkerTranscriptPath(cfg.ProjectRoot, sessionID)
					rt.TranscriptPath = transcriptPath
					runtimeMap[st.WorkerID] = rt
					runtimeDirty = true
				}
			}
			if provider == "codex" {
				if transcriptPath != "" && !transcriptLikelyFromCurrentLaunch(transcriptPath, launchedAt, sessionID) {
					delete(usedTranscriptPaths, expandHome(transcriptPath))
					transcriptPath = ""
					sessionID = ""
					rt.TranscriptPath = ""
					rt.SessionID = ""
					runtimeMap[st.WorkerID] = rt
					runtimeDirty = true
				}
				if transcriptPath == "" {
					path, discoveredID := discoverCodexWorkerTranscript(cfg.ProjectRoot, roleCfg.TranscriptGlob, launchedAt, usedTranscriptPaths)
					if path != "" {
						transcriptPath = path
						if sessionID == "" {
							sessionID = discoveredID
						}
						rt.WorkerID = st.WorkerID
						rt.Provider = provider
						rt.SessionID = sessionID
						rt.TranscriptPath = transcriptPath
						runtimeMap[st.WorkerID] = rt
						runtimeDirty = true
					}
				}
			}
			if transcriptPath != "" {
				usedTranscriptPaths[expandHome(transcriptPath)] = true
			}

			var snap tokenSnapshot
			if transcriptPath != "" {
				cacheKey := "path:" + expandHome(transcriptPath)
				if cached, ok := tokenCache[cacheKey]; ok {
					snap = cached
				} else {
					snap = computeTokenSnapshotFromPath(expandHome(transcriptPath))
					tokenCache[cacheKey] = snap
				}
			} else {
				glob := renderTemplate(strings.TrimSpace(roleCfg.TranscriptGlob), map[string]string{
					"session":      st.Session,
					"role":         st.Role,
					"worker_id":    st.WorkerID,
					"worker_slug":  slug(st.WorkerID),
					"session_id":   sessionID,
					"pane":         strconv.Itoa(st.Pane),
					"project_root": cfg.ProjectRoot,
				})
				cacheKey := "glob:" + glob
				if cached, ok := tokenCache[cacheKey]; ok {
					snap = cached
				} else {
					snap = computeTokenSnapshot(glob)
					tokenCache[cacheKey] = snap
				}
			}
			st.TokenPerMinute = snap.TokenPerMinute
			st.TranscriptAge = snap.Age
			if transcriptPath != "" {
				if beacon, ok := latestSwarmBeacon(provider, expandHome(transcriptPath)); ok {
					latestBeacon = beacon
					hasBeacon = true
				}
			}

			if st.State == "ready" && cfg.IdleSeconds > 0 && snap.Age > 0 && snap.Age < time.Duration(cfg.IdleSeconds)*time.Second {
				st.Reason = "recent-transcript"
			}
		}

		if st.State == "ready" && cfg.IdleSeconds > 0 {
			idleCutoff := idleCutoffForWorker(cfg, st.Provider)
			if st.TranscriptAge > idleCutoff {
				st.State = "waiting"
				st.Reason = "ready-transcript-idle"
			} else if st.ActivityAge > idleCutoff && (st.TranscriptAge == 0 || st.TranscriptAge > idleCutoff) {
				st.State = "waiting"
				st.Reason = "ready-pane-idle"
			}
		}

		if st.State == "busy" && strings.TrimSpace(st.BeadID) != "" && cfg.IdleSeconds > 0 {
			idleCutoff := idleCutoffForWorker(cfg, st.Provider)
			if normalizeProvider(st.Provider) == "codex" {
				// Codex can pause UI output briefly; prefer dual-signal idle, but allow
				// transcript-only idle when pane activity timestamp is unavailable.
				if shouldMarkCodexAssignedWaiting(st, idleCutoff) {
					st.State = "waiting"
					st.Reason = "assigned-idle"
				}
			} else {
				if st.TranscriptAge > idleCutoff {
					st.State = "waiting"
					st.Reason = "transcript-idle"
				} else if st.ActivityAge > idleCutoff && (st.TranscriptAge == 0 || st.TranscriptAge > idleCutoff) {
					st.State = "waiting"
					st.Reason = "assigned-idle"
				}
			}
		}
		if st.State == "busy" && strings.TrimSpace(st.BeadID) != "" {
			if stateHint, reason, _ := detectPaneStateHint(st.Session, st.Pane); stateHint != "" {
				// Codex idle UI can appear between short work bursts and causes flapping.
				// For codex, only accept waiting when we also have idle-age evidence.
				if stateHint == "waiting" && normalizeProvider(st.Provider) == "codex" {
					idleCutoff := idleCutoffForWorker(cfg, st.Provider)
					if shouldMarkCodexAssignedWaiting(st, idleCutoff) {
						st.State = stateHint
						st.Reason = reason
					}
				} else {
					st.State = stateHint
					st.Reason = reason
				}
			}
		}
		if hasBeacon {
			applyBeaconState(cfg, &st, latestBeacon)
		}

		st.Activity = buildActivity(st)
		rows = append(rows, st)
	}

	if runtimeDirty {
		_ = saveWorkerRuntimeMap(cfg.ProjectRoot, runtimeMap)
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Session != rows[j].Session {
			return rows[i].Session < rows[j].Session
		}
		if rows[i].Role != rows[j].Role {
			return rows[i].Role < rows[j].Role
		}
		return rows[i].Pane < rows[j].Pane
	})
	return rows, nil
}

func buildActivity(s WorkerStatus) string {
	parts := []string{}
	if s.ActivityAge > 0 {
		parts = append(parts, "pane:"+shortDur(s.ActivityAge))
	}
	if s.TranscriptAge > 0 {
		parts = append(parts, "transc:"+shortDur(s.TranscriptAge))
	}
	if s.TokenPerMinute > 0 {
		parts = append(parts, fmt.Sprintf("tok/min:%.0f", s.TokenPerMinute))
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, " ")
}

func shouldMarkCodexAssignedWaiting(st WorkerStatus, idleCutoff time.Duration) bool {
	if idleCutoff <= 0 || st.TokenPerMinute > 0 {
		return false
	}
	// Preferred: both signals show idle.
	if st.ActivityAge > idleCutoff && st.TranscriptAge > idleCutoff {
		return true
	}
	// Fallback for tmux builds where pane_activity is often unavailable/zero:
	// if transcript is stale for a long window, treat as waiting.
	if st.ActivityAge <= 0 && st.TranscriptAge > 3*idleCutoff {
		return true
	}
	return false
}

func idleCutoffForWorker(cfg Config, provider string) time.Duration {
	base := time.Duration(cfg.IdleSeconds) * time.Second
	if base <= 0 {
		return 0
	}
	// Codex interactive panes frequently pause for short bursts between actions.
	// Use a floor to reduce busy/waiting oscillation for assigned implementers.
	if normalizeProvider(provider) == "codex" && base < 60*time.Second {
		return 60 * time.Second
	}
	return base
}

func ensureSessionAndPanes(cfg Config) error {
	if !tmuxSessionExists(cfg.Session) {
		if _, err := runCommand("", "tmux", "new-session", "-d", "-s", cfg.Session, "-n", "swarm"); err != nil {
			return err
		}
	}

	panes, err := listPanes(cfg.Session, false)
	if err != nil {
		return err
	}
	paneByTitle := map[string]Pane{}
	unused := make([]Pane, 0)
	for _, p := range panes {
		paneByTitle[p.PaneTitle] = p
		if _, ok := parseWorkerTitle(p.PaneTitle); !ok {
			unused = append(unused, p)
		}
	}
	// Ensure style is applied for every known worker pane, including dynamic roles
	// like plan-review that may not be listed in config.roles.
	for _, p := range panes {
		if _, ok := parseWorkerTitle(p.PaneTitle); ok {
			applyPaneProfileStyle(cfg.Session, p.PaneIndex, p.PaneTitle)
		}
	}

	desiredByRole := desiredWorkersByRole(cfg)
	topologyChanged := false

	for _, role := range cfg.Roles {
		workers := desiredByRole[role.Name]
		for idx := 1; idx <= workers; idx++ {
			wid := workerID(cfg.Session, role.Name, idx)
			if existing, ok := paneByTitle[wid]; ok {
				applyPaneProfileStyle(cfg.Session, existing.PaneIndex, wid)
				if detached, reason, _ := detectPaneDetached(cfg.Session, existing.PaneIndex); detached {
					target := fmt.Sprintf("%s.%d", cfg.Session, existing.PaneIndex)
					_, _ = runCommand("", "tmux", "kill-pane", "-t", target)
					topologyChanged = true
					repl, err := splitPane(cfg.Session)
					if err != nil {
						return err
					}
					topologyChanged = true
					if err := setPaneTitle(cfg.Session, repl.PaneIndex, wid); err != nil {
						return err
					}
					applyPaneProfileStyle(cfg.Session, repl.PaneIndex, wid)
					maybeRegisterWorker(cfg, role, wid)
					if err := launchWorker(cfg, role, wid, repl.PaneIndex); err != nil {
						return err
					}
					fmt.Fprintf(os.Stderr, "warning: respawned detached pane %s (%s)\n", wid, reason)
					continue
				}
				if shellCommands[strings.ToLower(existing.CurrentCommand)] {
					maybeRegisterWorker(cfg, role, wid)
					if err := launchWorker(cfg, role, wid, existing.PaneIndex); err != nil {
						return err
					}
				}
				continue
			}

			var pane Pane
			if len(unused) > 0 {
				pane = unused[0]
				unused = unused[1:]
			} else {
				created, err := splitPane(cfg.Session)
				if err != nil {
					return err
				}
				pane = created
				topologyChanged = true
			}

			if err := setPaneTitle(cfg.Session, pane.PaneIndex, wid); err != nil {
				return err
			}
			applyPaneProfileStyle(cfg.Session, pane.PaneIndex, wid)
			maybeRegisterWorker(cfg, role, wid)
			if err := launchWorker(cfg, role, wid, pane.PaneIndex); err != nil {
				return err
			}
		}
		// Scale-down: remove excess worker panes for this role when desired workers drop.
		maxWorkers := max(1, role.Workers)
		for idx := workers + 1; idx <= maxWorkers; idx++ {
			wid := workerID(cfg.Session, role.Name, idx)
			if p, ok := paneByTitle[wid]; ok {
				_, _ = runCommand("", "tmux", "kill-pane", "-t", fmt.Sprintf("%s.%d", cfg.Session, p.PaneIndex))
				topologyChanged = true
			}
		}
	}

	// tmux can reset pane style after split/kill/layout changes; force full restyle once.
	if topologyChanged {
		paneStyleCache = map[string]string{}
		if refreshed, err := listPanes(cfg.Session, false); err == nil {
			for _, p := range refreshed {
				if _, ok := parseWorkerTitle(p.PaneTitle); ok {
					applyPaneProfileStyle(cfg.Session, p.PaneIndex, p.PaneTitle)
				}
			}
		}
	}

	_, err = runCommand("", "tmux", "select-layout", "-t", cfg.Session, "tiled")
	return err
}

func desiredWorkersByRole(cfg Config) map[string]int {
	desired := map[string]int{}
	for _, r := range cfg.Roles {
		desired[r.Name] = max(1, r.Workers)
	}

	beads, err := listBeads(cfg.ProjectRoot)
	if err != nil {
		return desired
	}
	queue := buildQueueByLabel(beads)
	assignedByRole := map[string]int{}
	for _, b := range beads {
		if wr, ok := parseWorkerTitle(strings.TrimSpace(b.Assignee)); ok {
			assignedByRole[wr.Role]++
		}
	}
	commitQ, _ := loadCommitQueue(cfg.ProjectRoot)

	flow, _ := loadFlowSpec(cfg.ProjectRoot)
	workersFromFlow := flowWorkersByRole(flow)
	for role, n := range workersFromFlow {
		if n > 0 {
			desired[role] = n
		}
	}

	for _, role := range cfg.Roles {
		hasWork := false
		switch strings.ToLower(strings.TrimSpace(role.Name)) {
		case "committer":
			hasWork = len(commitQ.Pending) > 0
		default:
			hasWork = len(queue[role.Label]) > 0
		}
		if !hasWork && assignedByRole[role.Name] == 0 {
			// Keep primary lanes warm to avoid pane churn (kill/recreate loops)
			// when queue briefly oscillates on event/fallback ticks.
			roleName := strings.ToLower(strings.TrimSpace(role.Name))
			if roleName == "committer" || roleName == "plan-review" {
				desired[role.Name] = 0
			}
		}
	}
	return desired
}

func flowWorkersByRole(flow FlowSpec) map[string]int {
	out := map[string]int{}
	for _, st := range flow.States {
		role := flowRoleFromState(st)
		if role == "" || st.Workers <= 0 {
			continue
		}
		out[role] = st.Workers
	}
	return out
}

func flowLifecyclePolicies(flow FlowSpec) map[string]WorkerLifecyclePolicy {
	out := map[string]WorkerLifecyclePolicy{}
	for _, st := range flow.States {
		role := flowRoleFromState(st)
		if role == "" {
			continue
		}
		p := WorkerLifecyclePolicy{
			Workers:                st.Workers,
			MaxIdle:                parseDurationish(st.MaxIdle),
			MaxLifetime:            parseDurationish(st.MaxLifetime),
			MaxBusyWithoutProgress: parseDurationish(st.MaxBusyWithoutProgress),
			Respawn:                parseBoolish(st.Respawn),
			OneShot:                parseBoolish(st.OneShot),
		}
		out[role] = p
	}
	return out
}

func parseDurationish(raw string) time.Duration {
	v := strings.TrimSpace(raw)
	if v == "" {
		return 0
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0
	}
	return d
}

func parseBoolish(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on", "enabled":
		return true
	default:
		return false
	}
}

func workerIdleAge(s WorkerStatus) time.Duration {
	a := s.ActivityAge
	t := s.TranscriptAge
	if a <= 0 {
		return t
	}
	if t <= 0 {
		return a
	}
	if a < t {
		return a
	}
	return t
}

func flowRoleFromState(st FlowState) string {
	lbl := strings.TrimSpace(st.Label)
	id := strings.ToLower(strings.TrimSpace(st.ID))
	switch lbl {
	case "needs-impl":
		return "implement"
	case "needs-proof":
		return "proof"
	case "needs-review":
		return "review"
	case "commit-queue":
		return "committer"
	case "plan-review":
		return "plan-review"
	}
	if strings.Contains(id, "committer") {
		return "committer"
	}
	if id == "plan.review" {
		return "plan-review"
	}
	return ""
}

func maybeRegisterWorker(cfg Config, role RoleConfig, workerID string) {
	if !cfg.AgentMail.Enabled || !cfg.AgentMail.AutoRegister {
		return
	}
	url := strings.TrimSpace(firstNonEmpty(cfg.AgentMail.URL, os.Getenv("AGENT_MAIL_URL")))
	if url == "" {
		return
	}
	token := firstNonEmpty(cfg.AgentMail.Token, os.Getenv("AGENT_MAIL_TOKEN"))

	projectKey := cfg.ProjectRoot
	if !filepath.IsAbs(projectKey) {
		if abs, err := filepath.Abs(projectKey); err == nil {
			projectKey = abs
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := callAgentMail(ctx, url, token, "ensure_project", map[string]any{"human_key": projectKey}); err != nil {
		fmt.Fprintf(os.Stderr, "agent-mail ensure_project failed (%s): %v\n", workerID, err)
		return
	}

	name := deterministicAgentName(workerID)
	prog := providerProgram(role.Provider)
	if prog == "" {
		prog = "bsw"
	}
	model := firstNonEmpty(role.Model, role.Provider)
	args := map[string]any{
		"project_key":        projectKey,
		"program":            prog,
		"model":              model,
		"name":               name,
		"task_description":   fmt.Sprintf("swarm role=%s worker=%s", role.Name, workerID),
		"attachments_policy": "inline",
	}
	if err := callAgentMail(ctx, url, token, "register_agent", args); err != nil {
		fallback := map[string]any{
			"project_key":      projectKey,
			"program":          prog,
			"model":            model,
			"task_description": fmt.Sprintf("swarm role=%s worker=%s", role.Name, workerID),
		}
		if err2 := callAgentMail(ctx, url, token, "register_agent", fallback); err2 != nil {
			fmt.Fprintf(os.Stderr, "agent-mail register failed (%s): %v\n", workerID, err2)
		}
	}
}

func callAgentMail(ctx context.Context, url, token, tool string, args map[string]any) error {
	reqBody := map[string]any{
		"jsonrpc": "2.0",
		"id":      fmt.Sprintf("swarm-%d", time.Now().UnixNano()),
		"method":  "tools/call",
		"params": map[string]any{
			"name":      tool,
			"arguments": args,
		},
	}
	buf, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if strings.TrimSpace(token) != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBuf, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("http %d: %s", resp.StatusCode, strings.TrimSpace(string(respBuf)))
	}

	var payload struct {
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(respBuf, &payload); err == nil && payload.Error != nil {
		return fmt.Errorf("rpc %d: %s", payload.Error.Code, payload.Error.Message)
	}
	return nil
}

func deterministicAgentName(workerID string) string {
	adjs := []string{"Blue", "Green", "Red", "Silver", "Golden", "Purple", "Amber", "Swift", "Bright", "Calm", "Bold", "Quiet"}
	nouns := []string{"Lake", "Stone", "River", "Cloud", "Falcon", "Cedar", "Summit", "Field", "Harbor", "Bridge", "Garden", "Valley"}

	h := sha1.Sum([]byte(workerID))
	a := int(h[0]) % len(adjs)
	n := int(h[1]) % len(nouns)
	return adjs[a] + nouns[n]
}

type profileTheme struct {
	RowBG  lipgloss.Color
	RowFG  lipgloss.Color
	TmuxBG string
	TmuxFG string
}

func roleThemeFor(role string) profileTheme {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "implement":
		return profileTheme{RowBG: lipgloss.Color("#1e3a8a"), RowFG: lipgloss.Color("#f8fbff"), TmuxBG: "colour33", TmuxFG: "colour255"}
	case "proof":
		return profileTheme{RowBG: lipgloss.Color("#92400e"), RowFG: lipgloss.Color("#fff8f2"), TmuxBG: "colour94", TmuxFG: "colour255"}
	case "review":
		return profileTheme{RowBG: lipgloss.Color("#166534"), RowFG: lipgloss.Color("#f3fff7"), TmuxBG: "colour28", TmuxFG: "colour255"}
	case "committer":
		return profileTheme{RowBG: lipgloss.Color("#6d28d9"), RowFG: lipgloss.Color("#f8f3ff"), TmuxBG: "colour56", TmuxFG: "colour255"}
	case "plan-review":
		return profileTheme{RowBG: lipgloss.Color("#b91c1c"), RowFG: lipgloss.Color("#fff5f5"), TmuxBG: "colour160", TmuxFG: "colour255"}
	default:
		return profileTheme{RowBG: lipgloss.Color("236"), RowFG: lipgloss.Color("252"), TmuxBG: "colour236", TmuxFG: "colour252"}
	}
}

func applyPaneProfileStyle(session string, pane int, workerID string) {
	role := ""
	if wr, ok := parseWorkerTitle(workerID); ok {
		role = wr.Role
	}
	theme := roleThemeFor(role)
	target := fmt.Sprintf("%s.%d", session, pane)
	cacheKey := target
	cacheVal := role + "|" + theme.TmuxBG + "|" + theme.TmuxFG
	if prev, ok := paneStyleCache[cacheKey]; ok && prev == cacheVal {
		return
	}
	style := fmt.Sprintf("bg=%s,fg=%s", theme.TmuxBG, theme.TmuxFG)
	if _, err := runCommand("", "tmux", "select-pane", "-t", target, "-P", style); err == nil {
		paneStyleCache[cacheKey] = cacheVal
	}
}

func renderRoleLegendLine() string {
	muted := lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	items := []struct {
		role string
	}{
		{role: "implement"},
		{role: "proof"},
		{role: "review"},
		{role: "committer"},
		{role: "plan-review"},
	}
	parts := make([]string, 0, len(items))
	for _, it := range items {
		t := roleThemeFor(it.role)
		pill := lipgloss.NewStyle().Background(t.RowBG).Foreground(t.RowFG).Render("  ")
		parts = append(parts, pill+muted.Render(" "+it.role))
	}
	return muted.Render("legend: " + strings.Join(parts, "  "))
}

func renderKeysLine(width int, keys string) string {
	muted := lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	line := "keys: " + strings.TrimSpace(keys)
	return muted.Render(reduce(line, max(20, width-2)))
}

func renderTickLogBlock(width int, headerWidth int, lines []string, logHeight int) string {
	headerStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("252"))
	mutedStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	var b strings.Builder
	b.WriteString(headerStyle.Render("tick log (latest)") + "\n")
	ruleW := min(max(20, headerWidth), max(20, width-1))
	b.WriteString(mutedStyle.Render(strings.Repeat("-", ruleW)) + "\n")
	logLines := lastNLogLines(lines, max(1, logHeight))
	if len(logLines) == 0 {
		b.WriteString(mutedStyle.Render("(no tick entries yet)") + "\n")
		return b.String()
	}
	for _, line := range logLines {
		b.WriteString(mutedStyle.Render(reduce(line, max(20, width-2))) + "\n")
	}
	return b.String()
}

func inferPlanState(meta SwarmMeta, flow WorkflowStageCounts, rows []WorkerStatus) string {
	if strings.TrimSpace(meta.PlanFile) == "" {
		return "none"
	}
	if (flow.QueueImpl + flow.QueueProof + flow.QueueReview + flow.InImplementation + flow.InProof + flow.InReview) > 0 {
		return "executing"
	}
	for _, r := range rows {
		if !strings.EqualFold(strings.TrimSpace(r.Role), "plan-review") {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(r.State)) {
		case "busy", "assigned", "waiting", "ready":
			return "plan-review"
		}
	}
	return "done"
}

func renderSystemStatusBlock(width int, flow WorkflowStageCounts, lifecycle LifecycleCounts, counts map[string]int, total int, meta SwarmMeta, rows []WorkerStatus) []string {
	out := []string{"system status"}
	planFile := strings.TrimSpace(meta.PlanFile)
	if planFile == "" {
		out = append(out, reduce("plan: none", max(20, width-2)))
	} else {
		out = append(out, reduce("plan: "+planFile, max(20, width-2)))
	}
	if len(meta.Topics) == 0 {
		out = append(out, reduce("topics: none", max(20, width-2)))
	} else {
		out = append(out, reduce("topics: "+strings.Join(meta.Topics, ", "), max(20, width-2)))
	}
	out = append(out, reduce("plan_state: "+inferPlanState(meta, flow, rows), max(20, width-2)))
	out = append(out, renderOverviewLines(counts, total, flow, lifecycle, width)...)
	return out
}

func sectionRule(width int) string {
	return strings.Repeat("-", min(70, max(20, width-1)))
}

func renderTabStrip(active int) string {
	tabs := []string{"sessions", "beads"}
	parts := make([]string, 0, len(tabs))
	on := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("230")).Background(lipgloss.Color("62")).Render
	off := lipgloss.NewStyle().Foreground(lipgloss.Color("244")).Render
	for i, t := range tabs {
		label := t
		if i == active {
			label = "[" + t + "]"
		}
		if i == active {
			parts = append(parts, on(" "+label+" "))
		} else {
			parts = append(parts, off(" "+label+" "))
		}
	}
	return strings.Join(parts, " ")
}

func renderOverviewLines(counts map[string]int, total int, flow WorkflowStageCounts, lifecycle LifecycleCounts, width int) []string {
	lines := make([]string, 0, 3)
	if counts == nil {
		counts = map[string]int{}
	}
	closed := counts["closed"]
	tomb := counts["tombstone"]
	active := total - closed - tomb
	if active < 0 {
		active = 0
	}
	_ = lifecycle
	lines = append(lines, reduce(fmt.Sprintf("beads: total=%d active=%d open=%d in_progress=%d deferred=%d closed=%d tomb=%d",
		total, active, counts["open"], counts["in_progress"], counts["deferred"], closed, tomb), max(20, width-2)))
	lines = append(lines, reduce(fmt.Sprintf("queues: impl=%d proof=%d review=%d | stages impl=%d proof=%d review=%d",
		flow.QueueImpl, flow.QueueProof, flow.QueueReview, flow.InImplementation, flow.InProof, flow.InReview), max(20, width-2)))
	lines = append(lines, reduce(fmt.Sprintf("assigned: impl=%d proof=%d review=%d other=%d unassigned=%d",
		flow.AssignedImpl, flow.AssignedProof, flow.AssignedReview, flow.AssignedOther, flow.Unassigned), max(20, width-2)))
	return lines
}

func providerProgram(provider string) string {
	switch normalizeProvider(provider) {
	case "codex":
		return "codex-cli"
	case "cc":
		return "claude-code"
	default:
		return "bsw"
	}
}

func normalizeProvider(provider string) string {
	p := strings.ToLower(strings.TrimSpace(provider))
	switch p {
	case "claude", "cc", "claude-code":
		return "cc"
	case "codex", "codex-cli":
		return "codex"
	case "":
		return "codex"
	default:
		return p
	}
}

func launchWorker(cfg Config, role RoleConfig, workerID string, pane int) error {
	if err := sendLine(cfg.Session, pane, "cd "+shellEscapeForLine(cfg.ProjectRoot)); err != nil {
		return err
	}
	// Give the shell a brief moment before sending the launch command.
	time.Sleep(100 * time.Millisecond)

	launch := strings.TrimSpace(role.LaunchCommand)
	if launch == "" {
		launch = buildLaunchCommand(role)
	}
	provider := normalizeProvider(role.Provider)
	templateSessionID := newUUIDv4()
	runtimeSessionID := ""
	if provider == "cc" {
		runtimeSessionID = templateSessionID
	}
	if err := recordWorkerLaunch(cfg.ProjectRoot, workerID, provider, runtimeSessionID); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to record worker runtime (%s): %v\n", workerID, err)
	}
	launch = renderTemplate(launch, map[string]string{
		"prompt_file": shellEscape(expandHome(role.PromptFile)),
		"role":        role.Name,
		"label":       role.Label,
		"worker_id":   workerID,
		"worker_slug": slug(workerID),
		"session_id":  shellEscape(templateSessionID),
		"session":     cfg.Session,
		"model":       shellEscape(role.Model),
		"effort":      shellEscape(role.Effort),
	})

	if err := sendLine(cfg.Session, pane, launch); err != nil {
		return err
	}
	return nil
}

func buildLaunchCommand(role RoleConfig) string {
	provider := normalizeProvider(role.Provider)
	model := strings.TrimSpace(role.Model)
	effort := strings.TrimSpace(role.Effort)
	promptPath := strings.TrimSpace(expandHome(role.PromptFile))
	prompt := shellEscape(promptPath)

	switch provider {
	case "cc":
		parts := []string{"claude", "--dangerously-skip-permissions"}
		if model != "" {
			parts = append(parts, "--model", shellEscape(model))
		}
		if effort != "" {
			parts = append(parts, "--effort", shellEscape(effort))
		}
		parts = append(parts, "--session-id", "{session_id}")
		cmd := strings.Join(parts, " ")
		if promptPath != "" {
			// Keep the prompt in-file and append it to avoid unsupported file flags.
			cmd += fmt.Sprintf(` --append-system-prompt "$(cat %s)"`, prompt)
		}
		return cmd
	default:
		parts := []string{"codex", "--dangerously-bypass-approvals-and-sandbox"}
		if model != "" {
			parts = append(parts, "-m", shellEscape(model))
		}
		if effort != "" {
			cfgArg := fmt.Sprintf(`model_reasoning_effort=%q`, effort)
			parts = append(parts, "-c", shellEscape(cfgArg))
		}
		parts = append(parts, "--search")
		cmd := strings.Join(parts, " ")
		if promptPath != "" {
			// Codex CLI reads system prompt reliably from env in current versions.
			cmd = fmt.Sprintf(`CODEX_SYSTEM_PROMPT="$(cat %s)" %s`, prompt, cmd)
		}
		return cmd
	}
}

func splitPane(session string) (Pane, error) {
	format := fmt.Sprintf("#{session_name}%[1]s#{pane_id}%[1]s#{pane_index}%[1]s#{pane_title}%[1]s#{pane_current_command}%[1]s#{pane_start_time}%[1]s#{pane_activity}", tmuxFieldSep)
	out, err := runCommand("", "tmux", "split-window", "-t", session, "-d", "-P", "-F", format)
	if err != nil {
		return Pane{}, err
	}
	return parsePaneLine(strings.TrimRight(out, "\r\n"))
}

func tmuxSessionExists(session string) bool {
	_, err := runCommand("", "tmux", "has-session", "-t", session)
	return err == nil
}

func listPanes(session string, allSessions bool) ([]Pane, error) {
	args := []string{"list-panes"}
	if allSessions {
		args = append(args, "-a")
	} else {
		args = append(args, "-t", session)
	}
	format := fmt.Sprintf("#{session_name}%[1]s#{pane_id}%[1]s#{pane_index}%[1]s#{pane_title}%[1]s#{pane_current_command}%[1]s#{pane_start_time}%[1]s#{pane_activity}", tmuxFieldSep)
	args = append(args, "-F", format)

	out, err := runCommand("", "tmux", args...)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimRight(out, "\r\n"), "\n")
	panes := make([]Pane, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		pane, err := parsePaneLine(line)
		if err != nil {
			continue
		}
		pane.LastLine, _ = paneTailLine(pane.Session, pane.PaneIndex)
		panes = append(panes, pane)
	}
	return panes, nil
}

func parsePaneLine(line string) (Pane, error) {
	parts := strings.Split(line, tmuxFieldSep)
	if len(parts) < 5 {
		return Pane{}, fmt.Errorf("invalid pane line")
	}
	paneIdx, err := strconv.Atoi(parts[2])
	if err != nil {
		return Pane{}, err
	}
	startUnix := int64(0)
	activityUnix := int64(0)
	if len(parts) >= 6 {
		startUnix, _ = strconv.ParseInt(strings.TrimSpace(parts[5]), 10, 64)
	}
	if len(parts) >= 7 {
		activityUnix, _ = strconv.ParseInt(strings.TrimSpace(parts[6]), 10, 64)
	}

	return Pane{
		Session:        parts[0],
		PaneID:         parts[1],
		PaneIndex:      paneIdx,
		PaneTitle:      strings.TrimSpace(parts[3]),
		CurrentCommand: strings.TrimSpace(parts[4]),
		StartAt:        unixToTime(startUnix),
		ActivityAt:     unixToTime(activityUnix),
	}, nil
}

func paneTailLine(session string, pane int) (string, error) {
	out, err := runCommand("", "tmux", "capture-pane", "-p", "-t", fmt.Sprintf("%s.%d", session, pane), "-S", "-1")
	if err != nil {
		return "", err
	}
	lines := strings.Split(strings.ReplaceAll(out, "\r", ""), "\n")
	if len(lines) == 0 {
		return "", nil
	}
	return strings.TrimSpace(lines[len(lines)-1]), nil
}

func detectPaneStateHint(session string, pane int) (string, string, error) {
	out, err := runCommand("", "tmux", "capture-pane", "-p", "-t", fmt.Sprintf("%s.%d", session, pane), "-S", "-60")
	if err != nil {
		return "", "", err
	}
	lower := strings.ToLower(out)
	switch {
	case strings.Contains(lower, "selected model") && strings.Contains(lower, "run /model"):
		return "blocked", "model-unavailable", nil
	case strings.Contains(lower, "session id") && strings.Contains(lower, "already in use"):
		return "blocked", "session-id-in-use", nil
	case strings.Contains(lower, "no recent activity") && strings.Contains(lower, "try \""):
		return "waiting", "agent-idle", nil
	case strings.Contains(lower, "for shortcuts") && strings.Contains(lower, "context left"):
		return "waiting", "agent-idle", nil
	}
	return "", "", nil
}

func detectPaneDetached(session string, pane int) (bool, string, error) {
	out, err := runCommand("", "tmux", "capture-pane", "-p", "-t", fmt.Sprintf("%s.%d", session, pane), "-S", "-120")
	if err != nil {
		return false, "", err
	}
	lower := strings.ToLower(out)
	type rule struct {
		reason   string
		patterns []string
	}
	rules := []rule{
		{reason: "session-ended", patterns: []string{"session has ended"}},
		{reason: "session-ended-enter", patterns: []string{"session ended", "press enter"}},
		{reason: "session-killed", patterns: []string{"session was killed"}},
		{reason: "session-missing", patterns: []string{"session no longer exists"}},
		{reason: "session-not-found", patterns: []string{"error: session not found"}},
		{reason: "session-cannot-resume", patterns: []string{"cannot resume session"}},
		{reason: "conversation-not-found", patterns: []string{"conversation not found"}},
		{reason: "resume-prompt", patterns: []string{"resume with", "session id"}},
	}
	for _, r := range rules {
		ok := true
		for _, p := range r.patterns {
			if !strings.Contains(lower, p) {
				ok = false
				break
			}
		}
		if ok {
			return true, r.reason, nil
		}
	}
	return false, "", nil
}

func setPaneTitle(session string, pane int, title string) error {
	target := fmt.Sprintf("%s.%d", session, pane)
	if _, err := runCommand("", "tmux", "select-pane", "-t", target, "-T", title); err != nil {
		return err
	}
	// Prevent agents from overwriting pane titles via OSC escape sequences.
	_, _ = runCommand("", "tmux", "set-option", "-p", "-t", target, "allow-set-title", "off")
	return nil
}

func sendLine(session string, pane int, line string) error {
	target := fmt.Sprintf("%s.%d", session, pane)
	if _, err := runCommand("", "tmux", "send-keys", "-t", target, "-l", "--", line); err != nil {
		return err
	}
	time.Sleep(120 * time.Millisecond)
	_, err := runCommand("", "tmux", "send-keys", "-t", target, "Enter")
	return err
}

func sendAgentPrompt(session string, pane int, prompt string) error {
	target := fmt.Sprintf("%s.%d", session, pane)
	if err := pasteBufferToPane(target, prompt); err != nil {
		// Fallback to literal send if buffer paste fails.
		return sendLine(session, pane, prompt)
	}
	time.Sleep(1 * time.Second)
	if _, err := runCommand("", "tmux", "send-keys", "-t", target, "Enter"); err != nil {
		return err
	}
	time.Sleep(500 * time.Millisecond)
	_, err := runCommand("", "tmux", "send-keys", "-t", target, "Enter")
	return err
}

func pasteBufferToPane(target string, content string) error {
	bufferName := fmt.Sprintf("bsw-%d", time.Now().UnixNano())
	cmd := exec.Command("tmux", "load-buffer", "-b", bufferName, "-")
	cmd.Stdin = strings.NewReader(content)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("tmux load-buffer: %s", msg)
	}
	if _, err := runCommand("", "tmux", "paste-buffer", "-p", "-d", "-b", bufferName, "-t", target); err != nil {
		_, _ = runCommand("", "tmux", "delete-buffer", "-b", bufferName)
		return err
	}
	return nil
}

func zoomPane(session string, pane int) error {
	_, _ = runCommand("", "tmux", "switch-client", "-t", session)
	if _, err := runCommand("", "tmux", "select-pane", "-t", fmt.Sprintf("%s.%d", session, pane), "-Z"); err == nil {
		return nil
	}
	cmd := exec.Command("tmux", "attach-session", "-t", session)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func buildQueueByLabel(beads []Bead) map[string][]Bead {
	queue := map[string][]Bead{}
	for _, b := range beads {
		if strings.TrimSpace(b.Assignee) != "" {
			continue
		}
		label := firstNeedsLabel(b.Labels)
		if label == "" {
			continue
		}
		queue[label] = append(queue[label], b)
	}
	for label := range queue {
		sort.Slice(queue[label], func(i, j int) bool {
			a := queue[label][i]
			b := queue[label][j]
			if a.Priority != b.Priority {
				return a.Priority < b.Priority
			}
			return a.UpdatedAt < b.UpdatedAt
		})
	}
	return queue
}

func assignBead(cfg Config, bead Bead, workerID string) error {
	args := []string{"update", bead.ID, "--assignee", workerID, "--actor", cfg.Actor}
	if strings.TrimSpace(bead.Owner) == "" {
		args = append(args, "--owner", workerID)
	}
	if strings.EqualFold(bead.Status, "open") {
		args = append(args, "--status", "in_progress")
	}
	_, err := runCommand(cfg.ProjectRoot, "br", args...)
	return err
}

func reconcileBeadTransitions(cfg Config, beads []Bead) (int, error) {
	latestState, err := readLatestStateByBead(cfg.ProjectRoot)
	if err != nil {
		return 0, nil // best effort: don't block scheduler on history parsing
	}
	flow, _ := loadFlowSpec(cfg.ProjectRoot)
	changed := 0
	for _, bead := range beads {
		sig := strings.ToLower(strings.TrimSpace(latestState[bead.ID]))
		targetLabel, shouldClose, ok := transitionTargetForSignal(flow, bead, sig)
		if !ok {
			continue
		}
		needsChanged := false
		hasTarget := false
		for _, l := range bead.Labels {
			if !strings.HasPrefix(strings.TrimSpace(l), "needs-") {
				continue
			}
			if targetLabel != "" && strings.EqualFold(strings.TrimSpace(l), targetLabel) {
				hasTarget = true
				continue
			}
			needsChanged = true
		}
		if targetLabel != "" && !hasTarget {
			needsChanged = true
		}
		needsClearAssignee := strings.TrimSpace(bead.Assignee) != ""
		needsClose := shouldClose && !strings.EqualFold(strings.TrimSpace(bead.Status), "closed")
		if !needsChanged && !needsClearAssignee && !needsClose {
			continue
		}
		if err := applyTransitionUpdate(cfg, bead, targetLabel, shouldClose); err != nil {
			return changed, err
		}
		changed++
	}
	return changed, nil
}

func transitionTargetForSignal(flow FlowSpec, bead Bead, sig string) (targetLabel string, shouldClose bool, ok bool) {
	if lbl, closeIt, found := transitionFromFlow(flow, bead, sig); found {
		return lbl, closeIt, true
	}
	switch strings.ToLower(strings.TrimSpace(sig)) {
	case "impl:done":
		return "needs-proof", false, true
	case "proof:failed":
		return "needs-impl", false, true
	case "proof:passed":
		return "needs-review", false, true
	case "review:failed":
		return "needs-impl", false, true
	case "review:passed":
		return "", true, true
	default:
		return "", false, false
	}
}

func transitionFromFlow(flow FlowSpec, bead Bead, sig string) (string, bool, bool) {
	if len(flow.Transitions) == 0 || len(flow.States) == 0 {
		return "", false, false
	}
	needs := firstNeedsLabel(bead.Labels)
	fromID := ""
	for _, st := range flow.States {
		if strings.EqualFold(strings.TrimSpace(st.Kind), "bead") && strings.EqualFold(strings.TrimSpace(st.Label), strings.TrimSpace(needs)) {
			fromID = st.ID
			break
		}
	}
	if fromID == "" {
		return "", false, false
	}
	event := "state:" + strings.ToLower(strings.TrimSpace(sig))
	var tr *FlowTransition
	for i := range flow.Transitions {
		t := &flow.Transitions[i]
		if strings.EqualFold(strings.TrimSpace(t.From), strings.TrimSpace(fromID)) &&
			strings.EqualFold(strings.TrimSpace(t.On), event) {
			tr = t
			break
		}
	}
	if tr == nil {
		return "", false, false
	}
	targetLabel := ""
	shouldClose := false
	for _, a := range tr.Actions {
		act := strings.TrimSpace(a)
		if strings.EqualFold(act, "close_bead") {
			shouldClose = true
			continue
		}
		if strings.HasPrefix(strings.ToLower(act), "set_label:") {
			targetLabel = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(act, "set_label:"), "set-label:"))
		}
	}
	if targetLabel == "" && strings.TrimSpace(tr.To) != "" {
		for _, st := range flow.States {
			if strings.EqualFold(strings.TrimSpace(st.ID), strings.TrimSpace(tr.To)) && strings.EqualFold(strings.TrimSpace(st.Kind), "bead") {
				targetLabel = strings.TrimSpace(st.Label)
				break
			}
		}
	}
	return targetLabel, shouldClose, true
}

func applyTransitionUpdate(cfg Config, bead Bead, targetLabel string, shouldClose bool) error {
	args := []string{"update", bead.ID, "--actor", cfg.Actor, "--assignee", ""}
	for _, l := range bead.Labels {
		trim := strings.TrimSpace(l)
		if !strings.HasPrefix(trim, "needs-") {
			continue
		}
		if targetLabel != "" && strings.EqualFold(trim, targetLabel) {
			continue
		}
		args = append(args, "--remove-label", trim)
	}
	if targetLabel != "" && !hasLabel(bead.Labels, targetLabel) {
		args = append(args, "--add-label", targetLabel)
	}
	if shouldClose {
		args = append(args, "--status", "closed")
	}
	_, err := runCommand(cfg.ProjectRoot, "br", args...)
	return err
}

func readLatestStateByBead(projectRoot string) (map[string]string, error) {
	path := filepath.Join(projectRoot, ".beads", "issues.jsonl")
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	type rawComment struct {
		Text string `json:"text"`
	}
	type rawIssue struct {
		ID       string       `json:"id"`
		Comments []rawComment `json:"comments"`
	}

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	latestIssue := map[string]rawIssue{}
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var issue rawIssue
		if err := json.Unmarshal([]byte(line), &issue); err != nil {
			continue
		}
		if strings.TrimSpace(issue.ID) == "" {
			continue
		}
		latestIssue[issue.ID] = issue
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	out := map[string]string{}
	for id, issue := range latestIssue {
		last := ""
		for _, c := range issue.Comments {
			matches := stateLinePattern.FindAllStringSubmatch(c.Text, -1)
			if len(matches) == 0 {
				continue
			}
			last = strings.ToLower(strings.TrimSpace(matches[len(matches)-1][1]))
		}
		if last != "" {
			out[id] = last
		}
	}
	return out, nil
}

func hasLabel(labels []string, target string) bool {
	target = strings.TrimSpace(target)
	for _, l := range labels {
		if strings.EqualFold(strings.TrimSpace(l), target) {
			return true
		}
	}
	return false
}

func autoCloseDormantRootBeads(cfg Config) (int, error) {
	latest, err := loadLatestIssueMeta(cfg.ProjectRoot)
	if err != nil {
		return 0, nil // best effort
	}
	closed := 0
	for _, issue := range latest {
		id := strings.TrimSpace(issue.ID)
		if id == "" {
			continue
		}
		status := strings.TrimSpace(issue.Status)
		if status != "open" && status != "in_progress" {
			continue
		}
		if strings.TrimSpace(issue.Assignee) != "" {
			continue
		}
		if firstNeedsLabel(issue.Labels) != "" {
			continue
		}
		// Only auto-close roots/epics that actually have descendants.
		prefix := id + "."
		hasAnyChild := false
		hasActiveChild := false
		for _, other := range latest {
			oid := strings.TrimSpace(other.ID)
			if !strings.HasPrefix(oid, prefix) {
				continue
			}
			hasAnyChild = true
			ost := strings.TrimSpace(other.Status)
			if ost == "open" || ost == "in_progress" {
				hasActiveChild = true
				break
			}
		}
		if !hasAnyChild || hasActiveChild {
			continue
		}
		if _, err := runCommand(cfg.ProjectRoot, "br", "close", id, "--reason", "auto-close: no active children", "--actor", cfg.Actor); err != nil {
			// non-fatal for one issue, keep going
			continue
		}
		closed++
	}
	return closed, nil
}

type issueMeta struct {
	ID       string   `json:"id"`
	Status   string   `json:"status"`
	Assignee string   `json:"assignee"`
	Labels   []string `json:"labels"`
}

func loadLatestIssueMeta(projectRoot string) ([]issueMeta, error) {
	path := filepath.Join(projectRoot, ".beads", "issues.jsonl")
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	latest := map[string]issueMeta{}
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var row issueMeta
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			continue
		}
		if strings.TrimSpace(row.ID) == "" {
			continue
		}
		latest[row.ID] = row
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	out := make([]issueMeta, 0, len(latest))
	for _, v := range latest {
		out = append(out, v)
	}
	return out, nil
}

func assignmentMessage(status WorkerStatus, bead Bead, role RoleConfig) string {
	var b strings.Builder
	fmt.Fprintf(&b, "ASSIGN role=%s provider=%s model=%s effort=%s bead=%s label=%s\n",
		status.Role, status.Provider, status.Model, status.Effort, bead.ID, role.Label)
	fmt.Fprintf(&b, "BEAD_TITLE: %s\n", bead.Title)
	if desc := strings.TrimSpace(bead.Description); desc != "" {
		fmt.Fprintf(&b, "BEAD_DESCRIPTION:\n%s\n", trimTo(desc, 12000))
	}
	fmt.Fprintf(&b, "WORKFLOW_RULES: %s\n", assignmentFlowRules(status.Role))
	fmt.Fprintf(&b, "LIFECYCLE_GUARDRAIL: %s\n", emergencyLifecycleGuidance(status.Role, bead.ID))

	promptPath := expandHome(role.PromptFile)
	promptBody := readFileBestEffort(promptPath)
	if promptBody != "" {
		fmt.Fprintf(&b, "\nROLE_PROMPT (%s):\n%s\n", promptPath, promptBody)
	} else {
		fmt.Fprintf(&b, "\nROLE_PROMPT_FILE: %s\n", promptPath)
	}
	return b.String()
}

func nudgeMessage(status WorkerStatus, bead Bead, role RoleConfig) string {
	var b strings.Builder
	fmt.Fprintf(&b, "NUDGE role=%s provider=%s model=%s effort=%s bead=%s label=%s\n",
		status.Role, status.Provider, status.Model, status.Effort, bead.ID, role.Label)
	fmt.Fprintf(&b, "You are already assigned to this bead. Continue the current step only.\n")
	fmt.Fprintf(&b, "If finished, write STATE result to the bead comment and stop.\n")
	fmt.Fprintf(&b, "Do not restart from scratch.\n")
	fmt.Fprintf(&b, "%s\n", emergencyLifecycleGuidance(status.Role, bead.ID))
	return b.String()
}

func committerAssignmentMessage(status WorkerStatus, beadID string, role RoleConfig) string {
	var b strings.Builder
	fmt.Fprintf(&b, "ASSIGN role=%s provider=%s model=%s effort=%s bead=%s label=%s\n",
		status.Role, status.Provider, status.Model, status.Effort, beadID, role.Label)
	fmt.Fprintf(&b, "BEAD_ID: %s\n", beadID)
	fmt.Fprintf(&b, "TASK: Commit finalized work for this bead. If already committed, write STATE: commit:done and stop.\n")
	promptPath := expandHome(role.PromptFile)
	promptBody := readFileBestEffort(promptPath)
	if promptBody != "" {
		fmt.Fprintf(&b, "\nROLE_PROMPT (%s):\n%s\n", promptPath, promptBody)
	}
	return b.String()
}

func emergencyLifecycleGuidance(role, beadID string) string {
	beadID = strings.TrimSpace(beadID)
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "implement":
		return fmt.Sprintf("If latest state is already impl:done, do not re-implement. Repair lifecycle: `br update %s --remove-label needs-impl --add-label needs-proof --assignee \"\" --actor bsw`, then stop.", beadID)
	case "proof":
		return fmt.Sprintf("If latest state is already proof:passed/proof:failed, do not re-proof. Repair lifecycle now: pass -> `br update %s --remove-label needs-proof --add-label needs-review --assignee \"\" --actor bsw`; fail -> `br update %s --remove-label needs-proof --add-label needs-impl --assignee \"\" --actor bsw`; then stop.", beadID, beadID)
	case "review":
		return fmt.Sprintf("If latest state is already review:passed/review:failed, do not re-review. Repair lifecycle now: passed -> `br update %s --remove-label needs-review --assignee \"\" --status closed --actor bsw`; failed -> `br update %s --remove-label needs-review --add-label needs-impl --assignee \"\" --actor bsw`; then stop.", beadID, beadID)
	default:
		return "If assignment is duplicate/replayed, do not redo work. Repair labels/assignee to the correct next stage and stop."
	}
}

func initMessage(workerID string, role RoleConfig) string {
	beaconRole := swarmBeaconRoleName(role.Name)
	var b strings.Builder
	fmt.Fprintf(&b, "INIT role=%s worker=%s\n", role.Name, workerID)
	fmt.Fprintf(&b, "You are a dedicated %s worker in this bsw swarm.\n", role.Name)
	fmt.Fprintf(&b, "No bead is assigned right now. Wait for ASSIGN messages.\n")
	fmt.Fprintf(&b, "First, print this exact line:\n")
	fmt.Fprintf(&b, "SWARM_STATUS role=%s state=WAITING\n", beaconRole)
	fmt.Fprintf(&b, "Then stay idle until the next ASSIGN.\n")
	return b.String()
}

func swarmBeaconRoleName(role string) string {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "implement":
		return "WORKER"
	case "proof":
		return "PROOFER"
	case "review":
		return "REVIEWER"
	default:
		return strings.ToUpper(strings.TrimSpace(role))
	}
}

func sendInitPromptToWorker(cfg Config, role RoleConfig, workerID string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		panes, err := listPanes(cfg.Session, false)
		if err != nil {
			return err
		}
		found := false
		for _, p := range panes {
			if p.PaneTitle != workerID {
				continue
			}
			found = true
			if shellCommands[strings.ToLower(strings.TrimSpace(p.CurrentCommand))] {
				break
			}
			return sendAgentPrompt(cfg.Session, p.PaneIndex, initMessage(workerID, role))
		}
		if time.Now().After(deadline) {
			if !found {
				return errors.New("worker pane not found")
			}
			return errors.New("worker pane is still shell")
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func assignmentFlowRules(role string) string {
	switch role {
	case "implement":
		return "On done: STATE impl:done NEXT proof; move needs-impl->needs-proof; clear assignee."
	case "proof":
		return "PASS: STATE proof:passed NEXT review, move needs-proof->needs-review, clear assignee. FAIL: STATE proof:failed NEXT impl, move needs-proof->needs-impl, clear assignee."
	case "review":
		return "PASS: STATE review:passed NEXT none, remove needs-review, clear assignee, close bead. FAIL: STATE review:failed NEXT impl, move needs-review->needs-impl, clear assignee."
	default:
		return ""
	}
}

func readFileBestEffort(path string) string {
	buf, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(buf))
}

func trimTo(s string, max int) string {
	s = strings.TrimSpace(s)
	if max <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "\n...[truncated]"
}

func listBeads(projectRoot string) ([]Bead, error) {
	var lastErr error
	for attempt := 0; attempt < 4; attempt++ {
		out, err := runCommand(projectRoot, "br", "list", "--status", "open", "--status", "in_progress", "--json", "--limit", "0")
		if err != nil {
			lastErr = err
			msg := strings.ToLower(err.Error())
			if strings.Contains(msg, "config_error") || strings.Contains(msg, "invalid json") || strings.Contains(msg, "trailing input") {
				time.Sleep(time.Duration(120*(attempt+1)) * time.Millisecond)
				continue
			}
			return nil, err
		}
		if strings.TrimSpace(out) == "" {
			return []Bead{}, nil
		}
		var beads []Bead
		if err := json.Unmarshal([]byte(out), &beads); err != nil {
			lastErr = fmt.Errorf("parse br list json: %w", err)
			time.Sleep(time.Duration(120*(attempt+1)) * time.Millisecond)
			continue
		}
		return beads, nil
	}
	// Fallback: if `br list` fails (often transient parser/config issues),
	// read directly from project-local JSONL so daemon/tui/status keep working.
	if beads, fbErr := listBeadsFromJSONL(projectRoot); fbErr == nil {
		return beads, nil
	}
	if lastErr == nil {
		lastErr = errors.New("unknown br list failure")
	}
	return nil, fmt.Errorf("br list failed after retries: %w", lastErr)
}

func listBeadsFromJSONL(projectRoot string) ([]Bead, error) {
	path := filepath.Join(projectRoot, ".beads", "issues.jsonl")
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	// Allow large lines due long markdown descriptions/comments in beads.
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	latest := map[string]Bead{}
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var b Bead
		if err := json.Unmarshal([]byte(line), &b); err != nil {
			continue
		}
		if b.ID == "" {
			continue
		}
		latest[b.ID] = b
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	beads := make([]Bead, 0, len(latest))
	for _, b := range latest {
		switch strings.TrimSpace(b.Status) {
		case "open", "in_progress":
			beads = append(beads, b)
		}
	}
	sort.Slice(beads, func(i, j int) bool {
		if beads[i].Priority != beads[j].Priority {
			return beads[i].Priority < beads[j].Priority
		}
		if beads[i].CreatedAt != beads[j].CreatedAt {
			return beads[i].CreatedAt < beads[j].CreatedAt
		}
		return beads[i].ID < beads[j].ID
	})
	return beads, nil
}

func listBeadStatusCounts(projectRoot string) (map[string]int, int, error) {
	out, err := runCommand(projectRoot, "br", "count", "--by", "status", "--include-closed", "--json")
	if err != nil {
		return beadStatusCountsFromJSONL(projectRoot)
	}
	var payload struct {
		Total  int `json:"total"`
		Groups []struct {
			Group string `json:"group"`
			Count int    `json:"count"`
		} `json:"groups"`
	}
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		return nil, 0, err
	}
	counts := map[string]int{}
	for _, g := range payload.Groups {
		name := strings.TrimSpace(g.Group)
		if name == "" {
			continue
		}
		counts[name] = g.Count
	}
	return counts, payload.Total, nil
}

func beadStatusCountsFromJSONL(projectRoot string) (map[string]int, int, error) {
	path := filepath.Join(projectRoot, ".beads", "issues.jsonl")
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	latest := map[string]string{}
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var row struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		}
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			continue
		}
		if row.ID == "" {
			continue
		}
		latest[row.ID] = strings.TrimSpace(row.Status)
	}
	if err := sc.Err(); err != nil {
		return nil, 0, err
	}
	counts := map[string]int{}
	for _, st := range latest {
		if st == "" {
			st = "open"
		}
		counts[st]++
	}
	return counts, len(latest), nil
}

func listWorkflowStageCounts(projectRoot string) (WorkflowStageCounts, error) {
	beads, err := listBeads(projectRoot)
	if err != nil {
		return WorkflowStageCounts{}, err
	}
	var c WorkflowStageCounts
	for _, b := range beads {
		needs := firstNeedsLabel(b.Labels)
		switch needs {
		case "needs-impl":
			c.InImplementation++
		case "needs-proof":
			c.InProof++
		case "needs-review":
			c.InReview++
		}

		assignee := strings.TrimSpace(b.Assignee)
		if assignee == "" {
			c.Unassigned++
			switch needs {
			case "needs-impl":
				c.QueueImpl++
			case "needs-proof":
				c.QueueProof++
			case "needs-review":
				c.QueueReview++
			}
			continue
		}
		switch assigneeRole(assignee) {
		case "implement":
			c.AssignedImpl++
		case "proof":
			c.AssignedProof++
		case "review":
			c.AssignedReview++
		default:
			c.AssignedOther++
		}
	}
	return c, nil
}

func assigneeRole(assignee string) string {
	if wr, ok := parseWorkerTitle(strings.TrimSpace(assignee)); ok {
		return wr.Role
	}
	l := strings.ToLower(strings.TrimSpace(assignee))
	switch {
	case strings.Contains(l, ":implement:"):
		return "implement"
	case strings.Contains(l, ":proof:"):
		return "proof"
	case strings.Contains(l, ":review:"):
		return "review"
	default:
		return ""
	}
}

func formatBeadStatusLine(counts map[string]int, total int) string {
	if total <= 0 && len(counts) == 0 {
		return ""
	}
	active := counts["open"] + counts["in_progress"] + counts["deferred"]
	other := 0
	core := map[string]bool{
		"open":        true,
		"in_progress": true,
		"deferred":    true,
		"closed":      true,
		"tombstone":   true,
	}
	for k, v := range counts {
		if !core[k] {
			other += v
		}
	}
	line := fmt.Sprintf("beads: total=%d active=%d closed=%d tomb=%d", total, active, counts["closed"], counts["tombstone"])
	if other > 0 {
		line += fmt.Sprintf(" other=%d", other)
	}
	return line
}

func formatWorkflowStageLine(c WorkflowStageCounts) string {
	parts := []string{
		fmt.Sprintf("workflow in_implementation=%d", c.InImplementation),
		fmt.Sprintf("in_proof=%d", c.InProof),
		fmt.Sprintf("in_review=%d", c.InReview),
		fmt.Sprintf("assigned_impl=%d", c.AssignedImpl),
		fmt.Sprintf("assigned_proof=%d", c.AssignedProof),
		fmt.Sprintf("assigned_review=%d", c.AssignedReview),
		fmt.Sprintf("unassigned=%d", c.Unassigned),
	}
	if c.AssignedOther > 0 {
		parts = append(parts, fmt.Sprintf("assigned_other=%d", c.AssignedOther))
	}
	return strings.Join(parts, " | ")
}

func formatWorkflowNeedLine(c WorkflowStageCounts) string {
	return fmt.Sprintf("workflow queue: impl=%d proof=%d review=%d",
		c.QueueImpl, c.QueueProof, c.QueueReview)
}

func formatWorkflowAssignedLine(c WorkflowStageCounts) string {
	line := fmt.Sprintf("workflow assigned: impl=%d proof=%d review=%d unassigned=%d",
		c.AssignedImpl, c.AssignedProof, c.AssignedReview, c.Unassigned)
	if c.AssignedOther > 0 {
		line += fmt.Sprintf(" other=%d", c.AssignedOther)
	}
	return line
}

func formatLifecycleLine1(c LifecycleCounts) string {
	return fmt.Sprintf("lifecycle active: beads=%d proof_reject_beads=%d review_reject_beads=%d",
		c.ActiveBeads, c.ProofRejectBeads, c.ReviewRejectBeads)
}

func formatLifecycleLine2(c LifecycleCounts) string {
	return fmt.Sprintf("lifecycle events: impl_done=%d proof_failed=%d proof_passed=%d review_failed=%d review_passed=%d",
		c.ImplementationEvents, c.ProofRejectEvents, c.ProofPassEvents, c.ReviewRejectEvents, c.ReviewPassEvents)
}

func formatBeadStatusDetailLine(counts map[string]int) string {
	return fmt.Sprintf("beads by_status: open=%d inprog=%d deferred=%d",
		counts["open"], counts["in_progress"], counts["deferred"])
}

func lifecycleCountsFromJSONL(projectRoot string) (LifecycleCounts, error) {
	path := filepath.Join(projectRoot, ".beads", "issues.jsonl")
	f, err := os.Open(path)
	if err != nil {
		return LifecycleCounts{}, err
	}
	defer f.Close()

	type rawComment struct {
		Text string `json:"text"`
	}
	type rawIssue struct {
		ID       string       `json:"id"`
		Status   string       `json:"status"`
		Comments []rawComment `json:"comments"`
	}

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	latest := map[string]rawIssue{}
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var issue rawIssue
		if err := json.Unmarshal([]byte(line), &issue); err != nil {
			continue
		}
		if strings.TrimSpace(issue.ID) == "" {
			continue
		}
		latest[issue.ID] = issue
	}
	if err := sc.Err(); err != nil {
		return LifecycleCounts{}, err
	}

	var out LifecycleCounts
	for _, issue := range latest {
		status := strings.TrimSpace(issue.Status)
		if status != "open" && status != "in_progress" {
			continue
		}
		out.ActiveBeads++

		hadProofReject := false
		hadReviewReject := false
		for _, c := range issue.Comments {
			t := strings.ToLower(c.Text)
			out.ImplementationEvents += strings.Count(t, "state: impl:done")
			nProofReject := strings.Count(t, "state: proof:failed")
			nReviewReject := strings.Count(t, "state: review:failed")
			out.ProofRejectEvents += nProofReject
			out.ReviewRejectEvents += nReviewReject
			out.ProofPassEvents += strings.Count(t, "state: proof:passed")
			out.ReviewPassEvents += strings.Count(t, "state: review:passed")
			if nProofReject > 0 {
				hadProofReject = true
			}
			if nReviewReject > 0 {
				hadReviewReject = true
			}
		}
		if hadProofReject {
			out.ProofRejectBeads++
		}
		if hadReviewReject {
			out.ReviewRejectBeads++
		}
	}
	return out, nil
}

func listLifecycleBeadRows(projectRoot string) ([]LifecycleBeadRow, error) {
	path := filepath.Join(projectRoot, ".beads", "issues.jsonl")
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	type rawComment struct {
		Text      string `json:"text"`
		Author    string `json:"author"`
		CreatedAt string `json:"created_at"`
	}
	type rawIssue struct {
		ID       string       `json:"id"`
		Title    string       `json:"title"`
		Status   string       `json:"status"`
		Labels   []string     `json:"labels"`
		Assignee string       `json:"assignee"`
		Comments []rawComment `json:"comments"`
	}

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	latest := map[string]rawIssue{}
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var issue rawIssue
		if err := json.Unmarshal([]byte(line), &issue); err != nil {
			continue
		}
		if strings.TrimSpace(issue.ID) == "" {
			continue
		}
		latest[issue.ID] = issue
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	rows := make([]LifecycleBeadRow, 0, len(latest))
	for _, issue := range latest {
		row := LifecycleBeadRow{
			ID:       issue.ID,
			Title:    strings.TrimSpace(issue.Title),
			Stage:    lifecycleStage(firstNeedsLabel(issue.Labels)),
			Status:   blankDash(issue.Status),
			Assignee: blankDash(strings.TrimSpace(issue.Assignee)),
		}
		comments := append([]rawComment(nil), issue.Comments...)
		sort.SliceStable(comments, func(i, j int) bool {
			ti := parseMaybeRFC3339(comments[i].CreatedAt)
			tj := parseMaybeRFC3339(comments[j].CreatedAt)
			if ti.IsZero() && tj.IsZero() {
				return i < j
			}
			if ti.IsZero() {
				return false
			}
			if tj.IsZero() {
				return true
			}
			return ti.Before(tj)
		})
		commentTexts := make([]string, 0, len(issue.Comments))
		for _, c := range comments {
			commentTexts = append(commentTexts, c.Text)
		}
		row.Timeline = buildBeadTimeline(issue.Status, commentTexts)
		for _, c := range comments {
			t := strings.ToLower(c.Text)
			row.ImplDone += strings.Count(t, "state: impl:done")
			row.ProofFailed += strings.Count(t, "state: proof:failed")
			row.ProofPassed += strings.Count(t, "state: proof:passed")
			row.ReviewFailed += strings.Count(t, "state: review:failed")
			row.ReviewPassed += strings.Count(t, "state: review:passed")
			for _, ln := range strings.Split(c.Text, "\n") {
				trim := strings.TrimSpace(ln)
				if trim == "" {
					continue
				}
				if !strings.Contains(strings.ToLower(trim), "state:") {
					continue
				}
				head := ""
				if ts := strings.TrimSpace(c.CreatedAt); ts != "" {
					head = ts
				}
				if au := strings.TrimSpace(c.Author); au != "" {
					if head != "" {
						head += " "
					}
					head += au
				}
				if head != "" {
					row.History = append(row.History, head+" | "+trim)
				} else {
					row.History = append(row.History, trim)
				}
			}
		}
		if len(row.History) > 0 {
			row.LastState = row.History[len(row.History)-1]
			row.HistoryPreview = row.History[len(row.History)-1]
		} else {
			row.LastState = "-"
			row.HistoryPreview = "-"
		}
		row.Current = lifecycleCurrentKey(row)
		rows = append(rows, row)
	}

	currentRank := map[string]int{
		"open":        0,
		"implement":   1,
		"proof":       2,
		"review":      3,
		"closed":      4,
		"tombstone":   5,
		"deferred":    5,
		"in_progress": 6,
		"-":           7,
	}
	sort.Slice(rows, func(i, j int) bool {
		ri := currentRank[rows[i].Current]
		rj := currentRank[rows[j].Current]
		if ri != rj {
			return ri < rj
		}
		if rows[i].Stage != rows[j].Stage {
			return rows[i].Stage < rows[j].Stage
		}
		return rows[i].ID < rows[j].ID
	})
	return rows, nil
}

func parseMaybeRFC3339(v string) time.Time {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}
	}
	if ts, err := time.Parse(time.RFC3339Nano, v); err == nil {
		return ts
	}
	if ts, err := time.Parse(time.RFC3339, v); err == nil {
		return ts
	}
	return time.Time{}
}

func lifecycleCurrentKey(row LifecycleBeadRow) string {
	s := strings.ToLower(strings.TrimSpace(row.Status))
	if s == "closed" {
		return "closed"
	}
	switch strings.TrimSpace(row.Stage) {
	case "impl":
		return "implement"
	case "proof":
		return "proof"
	case "review":
		return "review"
	}
	if s == "open" {
		return "open"
	}
	if s == "deferred" {
		return "deferred"
	}
	if s == "tombstone" {
		return "tombstone"
	}
	if s == "in_progress" {
		return "in_progress"
	}
	return "-"
}

func buildBeadTimeline(status string, commentTexts []string) []string {
	out := []string{"open"}
	for _, txt := range commentTexts {
		lc := strings.ToLower(txt)
		for _, line := range strings.Split(lc, "\n") {
			t := strings.TrimSpace(line)
			switch {
			case strings.Contains(t, "state: impl:done"):
				out = append(out, "implement")
			case strings.Contains(t, "state: proof:passed"), strings.Contains(t, "state: proof:failed"):
				out = append(out, "proof")
			case strings.Contains(t, "state: review:passed"), strings.Contains(t, "state: review:failed"):
				out = append(out, "review")
			}
		}
	}
	if strings.EqualFold(strings.TrimSpace(status), "closed") {
		out = append(out, "closed")
	} else if strings.EqualFold(strings.TrimSpace(status), "tombstone") {
		out = append(out, "tombstone")
	}
	return out
}

func lifecycleStage(needs string) string {
	switch strings.TrimSpace(needs) {
	case "needs-impl":
		return "impl"
	case "needs-proof":
		return "proof"
	case "needs-review":
		return "review"
	default:
		return "-"
	}
}

func timelineSquareColor(key string) lipgloss.Color {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "open":
		return lipgloss.Color("#6b7280")
	case "implement":
		return roleThemeFor("implement").RowBG
	case "proof":
		return roleThemeFor("proof").RowBG
	case "review":
		return roleThemeFor("review").RowBG
	case "closed":
		// Reserved neon green for closed (intentionally distinct from role colors).
		return lipgloss.Color("#a3e635")
	case "tombstone":
		return lipgloss.Color("#111827")
	default:
		return lipgloss.Color("#9ca3af")
	}
}

func renderBeadTimelineSquares(events []string) string {
	if len(events) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(events))
	for _, e := range events {
		parts = append(parts, lipgloss.NewStyle().Foreground(timelineSquareColor(e)).Render("■"))
	}
	return strings.Join(parts, "")
}

func renderBeadTimelineCell(events []string, width int) string {
	if width < 1 {
		width = 1
	}
	s := renderBeadTimelineSquares(events)
	n := len(events)
	if n < width {
		s += strings.Repeat(" ", width-n)
	}
	return s
}

func renderTimelineLegendLine() string {
	muted := lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	keys := []string{"open", "implement", "proof", "review", "closed", "tombstone"}
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		sq := lipgloss.NewStyle().Foreground(timelineSquareColor(k)).Render("■")
		parts = append(parts, sq+muted.Render(k))
	}
	return muted.Render("timeline: ") + strings.Join(parts, muted.Render("  "))
}

func runCommand(cwd, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	if cwd != "" {
		cmd.Dir = cwd
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = strings.TrimSpace(stdout.String())
		}
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("%s %s: %s", name, strings.Join(args, " "), msg)
	}
	return stdout.String(), nil
}

func loadConfig(path string) (Config, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return Config{}, err
	}
	cfgPath := path
	if !filepath.IsAbs(cfgPath) {
		cfgPath = filepath.Join(cwd, cfgPath)
	}

	buf, err := os.ReadFile(cfgPath)
	if err != nil {
		return Config{}, err
	}
	planReviewEnabledExplicit := false
	var rawRoot map[string]json.RawMessage
	if err := json.Unmarshal(buf, &rawRoot); err == nil {
		if prRaw, ok := rawRoot["plan_reviewer"]; ok {
			var pr map[string]json.RawMessage
			if err := json.Unmarshal(prRaw, &pr); err == nil {
				_, planReviewEnabledExplicit = pr["enabled"]
			}
		}
	}
	var cfg Config
	if err := json.Unmarshal(buf, &cfg); err != nil {
		return Config{}, err
	}

	cfg.ProjectRoot = expandHome(cfg.ProjectRoot)
	if cfg.ProjectRoot == "" {
		cfg.ProjectRoot = cwd
	}
	if cfg.Actor == "" {
		cfg.Actor = defaultActor
	}
	for i := range cfg.Roles {
		cfg.Roles[i].PromptFile = expandHome(cfg.Roles[i].PromptFile)
	}
	if !hasRoleConfig(cfg.Roles, "committer") {
		committerPrompt := filepath.Join(cfg.ProjectRoot, ".bsw", "prompts", "impl_committer.md")
		if _, err := os.Stat(committerPrompt); err != nil {
			legacyPrompt := filepath.Join(cfg.ProjectRoot, "docs", "workflow", "prompts", "impl_committer.md")
			if _, lerr := os.Stat(legacyPrompt); lerr == nil {
				committerPrompt = legacyPrompt
			}
		}
		cfg.Roles = append(cfg.Roles, RoleConfig{
			Name:           "committer",
			Label:          "commit-queue",
			Workers:        1,
			Provider:       "cc",
			Model:          "opus",
			Effort:         "medium",
			PromptFile:     committerPrompt,
			LaunchCommand:  "",
			TranscriptGlob: "~/.claude/projects/*/*.jsonl",
		})
	}
	if strings.TrimSpace(cfg.PlanReview.Provider) == "" {
		cfg.PlanReview.Provider = "cc"
	}
	if strings.TrimSpace(cfg.PlanReview.Model) == "" {
		cfg.PlanReview.Model = "opus"
	}
	if strings.TrimSpace(cfg.PlanReview.Effort) == "" {
		cfg.PlanReview.Effort = "high"
	}
	if strings.TrimSpace(cfg.PlanReview.PromptFile) == "" {
		cfg.PlanReview.PromptFile = filepath.Join(cfg.ProjectRoot, ".bsw", "prompts", "plan_reviewer.md")
		if _, err := os.Stat(cfg.PlanReview.PromptFile); err != nil {
			legacyPrompt := filepath.Join(cfg.ProjectRoot, "docs", "workflow", "prompts", "plan_reviewer.md")
			if _, lerr := os.Stat(legacyPrompt); lerr == nil {
				cfg.PlanReview.PromptFile = legacyPrompt
			}
		}
	}
	// Backward-compatible default: enable plan reviewer when legacy config omitted the field.
	if !planReviewEnabledExplicit {
		cfg.PlanReview.Enabled = true
	}
	cfg.PlanReview.PromptFile = expandHome(cfg.PlanReview.PromptFile)
	return cfg, nil
}

func hasRoleConfig(roles []RoleConfig, name string) bool {
	for _, r := range roles {
		if strings.EqualFold(strings.TrimSpace(r.Name), strings.TrimSpace(name)) {
			return true
		}
	}
	return false
}

func validateConfig(cfg Config) error {
	if strings.TrimSpace(cfg.Session) == "" {
		return errors.New("config.session required")
	}
	if strings.TrimSpace(cfg.ProjectRoot) == "" {
		return errors.New("config.project_root required")
	}
	if len(cfg.Roles) == 0 {
		return errors.New("config.roles required")
	}
	seen := map[string]bool{}
	for _, r := range cfg.Roles {
		if r.Name == "" {
			return errors.New("role.name required")
		}
		if seen[r.Name] {
			return fmt.Errorf("duplicate role %s", r.Name)
		}
		seen[r.Name] = true
		if r.Label == "" {
			return fmt.Errorf("role %s missing label", r.Name)
		}
		if r.Workers < 1 {
			return fmt.Errorf("role %s workers must be >=1", r.Name)
		}
	}
	if cfg.PlanReview.Enabled && strings.TrimSpace(cfg.PlanReview.PromptFile) == "" {
		return errors.New("config.plan_reviewer.prompt_file required when enabled")
	}
	return nil
}

func writeJSON(path string, v any) error {
	buf, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, append(buf, '\n'), 0o644)
}

func firstNeedsLabel(labels []string) string {
	for _, l := range labels {
		if strings.HasPrefix(l, "needs-") {
			return l
		}
	}
	return ""
}

func parseWorkerTitle(title string) (WorkerRef, bool) {
	m := workerTitlePattern.FindStringSubmatch(strings.TrimSpace(title))
	if len(m) != 4 {
		return WorkerRef{}, false
	}
	idx, err := strconv.Atoi(m[3])
	if err != nil {
		return WorkerRef{}, false
	}
	return WorkerRef{Session: m[1], WorkerID: title, Role: m[2], Index: idx}, true
}

func workerID(session, role string, idx int) string {
	return fmt.Sprintf("%s:%s:%02d", session, role, idx)
}

func mapRoleConfig(roles []RoleConfig) map[string]RoleConfig {
	m := make(map[string]RoleConfig, len(roles))
	for _, r := range roles {
		m[r.Name] = r
	}
	return m
}

func workerRuntimePath(projectRoot string) string {
	return filepath.Join(projectRoot, ".bsw", "runtime", "workers.json")
}

func commitQueuePath(projectRoot string) string {
	return filepath.Join(projectRoot, ".bsw", "runtime", "commit_queue.json")
}

func loadWorkerRuntimeMap(projectRoot string) (map[string]WorkerRuntime, error) {
	path := workerRuntimePath(projectRoot)
	buf, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]WorkerRuntime{}, nil
		}
		return nil, err
	}
	var data WorkerRuntimeFile
	if err := json.Unmarshal(buf, &data); err != nil {
		return nil, err
	}
	if data.Workers == nil {
		data.Workers = map[string]WorkerRuntime{}
	}
	return data.Workers, nil
}

func saveWorkerRuntimeMap(projectRoot string, workers map[string]WorkerRuntime) error {
	path := workerRuntimePath(projectRoot)
	data := WorkerRuntimeFile{Workers: workers}
	return writeJSON(path, data)
}

func loadCommitQueue(projectRoot string) (CommitQueueFile, error) {
	path := commitQueuePath(projectRoot)
	buf, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return CommitQueueFile{Pending: []CommitJob{}}, nil
		}
		return CommitQueueFile{}, err
	}
	var q CommitQueueFile
	if err := json.Unmarshal(buf, &q); err != nil {
		return CommitQueueFile{}, err
	}
	if q.Pending == nil {
		q.Pending = []CommitJob{}
	}
	return q, nil
}

func saveCommitQueue(projectRoot string, q CommitQueueFile) error {
	return writeJSON(commitQueuePath(projectRoot), q)
}

func reconcileCommitQueue(latestState map[string]string, q *CommitQueueFile) bool {
	if q == nil {
		return false
	}
	changed := false
	for beadID, st := range latestState {
		s := strings.ToLower(strings.TrimSpace(st))
		if s == "review:passed" {
			if !hasCommitJob(*q, beadID) && !strings.EqualFold(latestState[beadID], "commit:done") {
				q.Pending = append(q.Pending, CommitJob{
					BeadID:     beadID,
					EnqueuedAt: time.Now().UTC().Format(time.RFC3339Nano),
				})
				changed = true
			}
			continue
		}
		if s == "commit:done" || s == "commit:failed" {
			if removeCommitJob(q, beadID) {
				changed = true
			}
		}
	}
	return changed
}

func hasCommitJob(q CommitQueueFile, beadID string) bool {
	for _, j := range q.Pending {
		if strings.EqualFold(strings.TrimSpace(j.BeadID), strings.TrimSpace(beadID)) {
			return true
		}
	}
	return false
}

func removeCommitJob(q *CommitQueueFile, beadID string) bool {
	if q == nil || len(q.Pending) == 0 {
		return false
	}
	out := make([]CommitJob, 0, len(q.Pending))
	removed := false
	for _, j := range q.Pending {
		if strings.EqualFold(strings.TrimSpace(j.BeadID), strings.TrimSpace(beadID)) {
			removed = true
			continue
		}
		out = append(out, j)
	}
	q.Pending = out
	return removed
}

func firstCommitJob(q CommitQueueFile) (CommitJob, bool) {
	if len(q.Pending) == 0 {
		return CommitJob{}, false
	}
	return q.Pending[0], true
}

func recordWorkerLaunch(projectRoot, workerID, provider, sessionID string) error {
	workers, err := loadWorkerRuntimeMap(projectRoot)
	if err != nil {
		return err
	}
	rt := workers[workerID]
	rt.WorkerID = workerID
	rt.Provider = provider
	rt.SessionID = strings.TrimSpace(sessionID)
	rt.TranscriptPath = ""
	rt.LaunchedAt = time.Now().UTC().Format(time.RFC3339Nano)
	workers[workerID] = rt
	return saveWorkerRuntimeMap(projectRoot, workers)
}

func parseWorkerLaunchTime(rt WorkerRuntime) time.Time {
	if strings.TrimSpace(rt.LaunchedAt) == "" {
		return time.Time{}
	}
	if ts, err := time.Parse(time.RFC3339Nano, rt.LaunchedAt); err == nil {
		return ts
	}
	if ts, err := time.Parse(time.RFC3339, rt.LaunchedAt); err == nil {
		return ts
	}
	return time.Time{}
}

func parseRuntimeTime(raw string) time.Time {
	v := strings.TrimSpace(raw)
	if v == "" {
		return time.Time{}
	}
	if ts, err := time.Parse(time.RFC3339Nano, v); err == nil {
		return ts
	}
	if ts, err := time.Parse(time.RFC3339, v); err == nil {
		return ts
	}
	return time.Time{}
}

func shouldNudgeAssignedWorker(rt WorkerRuntime, now time.Time, cooldown time.Duration) bool {
	if cooldown <= 0 {
		return true
	}
	last := parseRuntimeTime(rt.LastNudgeAt)
	if last.IsZero() {
		return true
	}
	return now.Sub(last) >= cooldown
}

func shouldReleaseStuckAssignment(cfg Config, st WorkerStatus, bead Bead) bool {
	if strings.TrimSpace(st.BeadID) == "" || st.State != "waiting" {
		return false
	}
	idle := idleCutoffForWorker(cfg, st.Provider)
	if idle <= 0 {
		idle = 45 * time.Second
	}
	workerIdle := st.TranscriptAge > idle || st.ActivityAge > idle
	if !workerIdle {
		return false
	}
	beadUpdated := parseRuntimeTime(bead.UpdatedAt)
	if beadUpdated.IsZero() {
		return false
	}
	stuckWindow := 3 * idle
	if stuckWindow < 2*time.Minute {
		stuckWindow = 2 * time.Minute
	}
	return time.Since(beadUpdated) > stuckWindow
}

func pickAssignableBeadForWorker(rt WorkerRuntime, queue []Bead, now time.Time, cooldown time.Duration) (Bead, []Bead) {
	if len(queue) == 0 {
		return Bead{}, queue
	}
	for i, b := range queue {
		if canAssignBeadToWorker(rt, b.ID, now, cooldown) {
			remaining := make([]Bead, 0, len(queue)-1)
			remaining = append(remaining, queue[:i]...)
			remaining = append(remaining, queue[i+1:]...)
			return b, remaining
		}
	}
	return Bead{}, queue
}

func canAssignBeadToWorker(rt WorkerRuntime, beadID string, now time.Time, cooldown time.Duration) bool {
	if strings.TrimSpace(beadID) == "" {
		return false
	}
	if cooldown <= 0 {
		return true
	}
	if !strings.EqualFold(strings.TrimSpace(rt.LastReleasedBead), strings.TrimSpace(beadID)) {
		return true
	}
	last := parseRuntimeTime(rt.LastReleasedAt)
	if last.IsZero() {
		return true
	}
	return now.Sub(last) >= cooldown
}

func transcriptLikelyFromCurrentLaunch(path string, launchedAt time.Time, sessionID string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	if launchedAt.IsZero() {
		// Unknown launch time is ambiguous; force re-discovery instead of trusting stale bindings.
		return false
	}
	info, err := os.Stat(expandHome(path))
	if err != nil {
		return false
	}
	if strings.TrimSpace(sessionID) != "" {
		base := filepath.Base(strings.TrimSpace(path))
		if !strings.Contains(base, strings.TrimSpace(sessionID)) {
			return false
		}
	}
	// If transcript metadata has a session start, ensure it is near/after this worker launch.
	// This prevents stale previous-day sessions from being reused when pane survives rebinding.
	if meta, ok := loadCodexSessionMeta(expandHome(path)); ok && !meta.StartedAt.IsZero() {
		if meta.StartedAt.Before(launchedAt.Add(-10 * time.Minute)) {
			return false
		}
	}
	return !info.ModTime().Before(launchedAt.Add(-2 * time.Minute))
}

func discoverCodexWorkerTranscript(projectRoot, glob string, launchedAt time.Time, used map[string]bool) (string, string) {
	expanded := expandHome(strings.TrimSpace(glob))
	if expanded == "" {
		expanded = expandHome("~/.codex/sessions/*/*/*/rollout-*.jsonl")
	}
	files, err := filepath.Glob(expanded)
	if err != nil || len(files) == 0 {
		return "", ""
	}
	projectAbs := absPathBestEffort(projectRoot)

	type cand struct {
		Path      string
		SessionID string
		StartedAt time.Time
		ModTime   time.Time
	}
	candidates := make([]cand, 0, len(files))
	for _, path := range files {
		absPath := expandHome(path)
		if used[absPath] {
			continue
		}
		info, err := os.Stat(absPath)
		if err != nil || info.IsDir() {
			continue
		}
		if !launchedAt.IsZero() && info.ModTime().Before(launchedAt.Add(-30*time.Minute)) {
			continue
		}

		meta, ok := loadCodexSessionMeta(absPath)
		if !ok {
			continue
		}
		if absPathBestEffort(meta.CWD) != projectAbs {
			continue
		}
		startedAt := meta.StartedAt
		if startedAt.IsZero() {
			startedAt = info.ModTime()
		}
		candidates = append(candidates, cand{
			Path:      absPath,
			SessionID: meta.ID,
			StartedAt: startedAt,
			ModTime:   info.ModTime(),
		})
	}
	if len(candidates) == 0 {
		return "", ""
	}

	if !launchedAt.IsZero() {
		recent := make([]cand, 0, len(candidates))
		cutoff := launchedAt.Add(-2 * time.Minute)
		for _, c := range candidates {
			if c.ModTime.After(cutoff) {
				recent = append(recent, c)
			}
		}
		if len(recent) > 0 {
			sort.Slice(recent, func(i, j int) bool {
				return recent[i].ModTime.After(recent[j].ModTime)
			})
			top := recent[0]
			return top.Path, top.SessionID
		}
	}

	sort.Slice(candidates, func(i, j int) bool {
		if launchedAt.IsZero() {
			return candidates[i].ModTime.After(candidates[j].ModTime)
		}
		di := candidates[i].StartedAt.Sub(launchedAt)
		if di < 0 {
			di = -di
		}
		dj := candidates[j].StartedAt.Sub(launchedAt)
		if dj < 0 {
			dj = -dj
		}
		if di != dj {
			return di < dj
		}
		return candidates[i].ModTime.After(candidates[j].ModTime)
	})

	top := candidates[0]
	return top.Path, top.SessionID
}

func loadCodexSessionMeta(path string) (CodexSessionMeta, bool) {
	line, err := readFirstLine(path, 8*1024*1024)
	if err != nil || len(line) == 0 {
		return CodexSessionMeta{}, false
	}
	var row struct {
		Type    string `json:"type"`
		Payload struct {
			ID        string `json:"id"`
			Timestamp string `json:"timestamp"`
			CWD       string `json:"cwd"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(line, &row); err != nil {
		return CodexSessionMeta{}, false
	}
	if row.Type != "session_meta" {
		return CodexSessionMeta{}, false
	}
	started, _ := time.Parse(time.RFC3339Nano, row.Payload.Timestamp)
	id := strings.TrimSpace(row.Payload.ID)
	if id == "" {
		if m := uuidInFilename.FindStringSubmatch(path); len(m) > 1 {
			id = strings.ToLower(strings.TrimSpace(m[1]))
		}
	}
	return CodexSessionMeta{
		ID:        id,
		CWD:       strings.TrimSpace(row.Payload.CWD),
		StartedAt: started,
	}, true
}

func latestSwarmBeacon(provider, transcriptPath string) (SwarmBeacon, bool) {
	buf, err := tailFile(transcriptPath, 2*1024*1024)
	if err != nil || len(buf) == 0 {
		return SwarmBeacon{}, false
	}

	var best SwarmBeacon
	found := false
	sc := bufio.NewScanner(bytes.NewReader(buf))
	sc.Buffer(make([]byte, 8*1024), 8*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || !strings.Contains(line, "SWARM_STATUS") {
			continue
		}

		var row map[string]json.RawMessage
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			continue
		}
		ts := parseJSONTimestamp(row["timestamp"])

		var texts []string
		switch normalizeProvider(provider) {
		case "cc":
			texts = extractClaudeBeaconTexts(row)
		default:
			texts = extractCodexBeaconTexts(row)
		}
		if len(texts) == 0 {
			continue
		}

		for _, text := range texts {
			for _, beacon := range parseSwarmBeacons(text) {
				beacon.At = ts
				if !found {
					best = beacon
					found = true
					continue
				}
				// Keep scan-order fallback and prefer newer timestamp when present.
				if !beacon.At.IsZero() && !best.At.IsZero() {
					if beacon.At.After(best.At) || beacon.At.Equal(best.At) {
						best = beacon
					}
					continue
				}
				best = beacon
			}
		}
	}
	if !found {
		return SwarmBeacon{}, false
	}
	return best, true
}

func extractClaudeBeaconTexts(row map[string]json.RawMessage) []string {
	if parseJSONString(row["type"]) != "assistant" {
		return nil
	}
	msgRaw := row["message"]
	if len(msgRaw) == 0 {
		return nil
	}
	var msg map[string]json.RawMessage
	if err := json.Unmarshal(msgRaw, &msg); err != nil {
		return nil
	}
	texts := make([]string, 0, 4)
	if s := parseJSONString(msg["content"]); s != "" {
		texts = append(texts, s)
	}
	var parts []struct {
		Type    string `json:"type"`
		Text    string `json:"text"`
		Content string `json:"content"`
	}
	if err := json.Unmarshal(msg["content"], &parts); err == nil {
		for _, p := range parts {
			if t := strings.TrimSpace(firstNonEmpty(p.Text, p.Content)); t != "" {
				texts = append(texts, t)
			}
		}
	}
	return texts
}

func extractCodexBeaconTexts(row map[string]json.RawMessage) []string {
	rowType := parseJSONString(row["type"])
	if rowType != "response_item" && rowType != "event_msg" {
		return nil
	}
	payloadRaw := row["payload"]
	if len(payloadRaw) == 0 {
		return nil
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(payloadRaw, &payload); err != nil {
		return nil
	}
	payloadType := parseJSONString(payload["type"])
	texts := make([]string, 0, 6)

	switch rowType {
	case "event_msg":
		// Ignore user echoes to avoid matching prompt templates.
		if payloadType != "assistant_message" {
			return nil
		}
		if s := parseJSONString(payload["message"]); s != "" {
			texts = append(texts, s)
		}
	case "response_item":
		switch payloadType {
		case "message":
			if role := parseJSONString(payload["role"]); role != "assistant" {
				return nil
			}
			if s := parseJSONString(payload["text"]); s != "" {
				texts = append(texts, s)
			}
		case "function_call_output":
			if s := parseJSONString(payload["output"]); s != "" {
				texts = append(texts, s)
			}
		default:
			return nil
		}
	}

	var parts []struct {
		Type      string `json:"type"`
		Text      string `json:"text"`
		InputText string `json:"input_text"`
		Content   string `json:"content"`
	}
	if err := json.Unmarshal(payload["content"], &parts); err == nil {
		for _, p := range parts {
			if t := strings.TrimSpace(firstNonEmpty(p.Text, p.InputText, p.Content)); t != "" {
				texts = append(texts, t)
			}
		}
	}

	return texts
}

func parseSwarmBeacons(text string) []SwarmBeacon {
	lines := swarmBeaconLine.FindAllString(text, -1)
	if len(lines) == 0 {
		return nil
	}
	out := make([]SwarmBeacon, 0, len(lines))
	for _, line := range lines {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 3 || !strings.EqualFold(fields[0], "SWARM_STATUS") {
			continue
		}
		meta := map[string]string{}
		for _, f := range fields[1:] {
			idx := strings.IndexByte(f, '=')
			if idx <= 0 {
				continue
			}
			k := strings.ToLower(strings.TrimSpace(f[:idx]))
			v := strings.Trim(strings.TrimSpace(f[idx+1:]), `"'`)
			meta[k] = v
		}
		role := strings.TrimSpace(meta["role"])
		state := strings.TrimSpace(meta["state"])
		if role == "" || state == "" {
			continue
		}
		out = append(out, SwarmBeacon{
			Role:   strings.ToUpper(role),
			State:  strings.ToUpper(state),
			BeadID: strings.TrimSpace(meta["bead"]),
			Reason: strings.ToLower(strings.TrimSpace(meta["reason"])),
		})
	}
	return out
}

func parseJSONString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var v string
	if err := json.Unmarshal(raw, &v); err != nil {
		return ""
	}
	return strings.TrimSpace(v)
}

func parseJSONTimestamp(raw json.RawMessage) time.Time {
	v := parseJSONString(raw)
	if v == "" {
		return time.Time{}
	}
	if ts, err := time.Parse(time.RFC3339Nano, v); err == nil {
		return ts
	}
	if ts, err := time.Parse(time.RFC3339, v); err == nil {
		return ts
	}
	return time.Time{}
}

func applyBeaconState(cfg Config, st *WorkerStatus, beacon SwarmBeacon) {
	if st == nil {
		return
	}
	// Ignore beacons from other roles to avoid cross-pane transcript mismatches.
	expectedRole := swarmBeaconRoleName(st.Role)
	if strings.TrimSpace(beacon.Role) != "" && !strings.EqualFold(strings.TrimSpace(beacon.Role), strings.TrimSpace(expectedRole)) {
		return
	}
	if !beacon.At.IsZero() {
		age := time.Since(beacon.At)
		if age < 0 {
			age = 0
		}
		if age > beaconFreshWindow(cfg, st.Provider) {
			return
		}
	}

	switch strings.ToUpper(strings.TrimSpace(beacon.State)) {
	case "BLOCKED":
		st.State = "blocked"
		st.Reason = "beacon-blocked"
	case "WAITING":
		// Do not let WAITING override an assigned bead state; this causes busy/waiting flapping.
		if strings.TrimSpace(st.BeadID) != "" {
			return
		}
		st.State = "waiting"
		st.Reason = "beacon-waiting"
		if strings.EqualFold(strings.TrimSpace(st.Role), "plan-review") && strings.EqualFold(strings.TrimSpace(beacon.Reason), "plan_review_done") {
			st.State = "ready"
			st.Reason = "beacon-plan-review-done"
		}
	case "WORKING":
		if strings.TrimSpace(st.BeadID) != "" && (strings.TrimSpace(beacon.BeadID) == "" || strings.TrimSpace(beacon.BeadID) == strings.TrimSpace(st.BeadID)) {
			st.State = "busy"
			st.Reason = "beacon-working"
		}
	case "HANDOFF", "DONE":
		if strings.TrimSpace(st.BeadID) == "" {
			st.State = "ready"
			st.Reason = "beacon-" + strings.ToLower(strings.TrimSpace(beacon.State))
		}
	}
}

func beaconFreshWindow(cfg Config, provider string) time.Duration {
	idle := idleCutoffForWorker(cfg, provider)
	if idle <= 0 {
		idle = 45 * time.Second
	}
	w := 2 * idle
	if w < 60*time.Second {
		w = 60 * time.Second
	}
	if w > 20*time.Minute {
		w = 20 * time.Minute
	}
	return w
}

func readFirstLine(path string, maxBytes int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r := bufio.NewReader(io.LimitReader(f, maxBytes))
	line, err := r.ReadBytes('\n')
	if err != nil && err != io.EOF {
		return nil, err
	}
	return bytes.TrimSpace(line), nil
}

func absPathBestEffort(path string) string {
	v := expandHome(strings.TrimSpace(path))
	if v == "" {
		return ""
	}
	if abs, err := filepath.Abs(v); err == nil {
		v = abs
	}
	return filepath.Clean(v)
}

func computeTokenSnapshot(glob string) tokenSnapshot {
	path := latestGlobFile(glob)
	if path == "" {
		return tokenSnapshot{}
	}
	return computeTokenSnapshotFromPath(path)
}

func computeTokenSnapshotFromPath(path string) tokenSnapshot {
	info, err := os.Stat(path)
	if err != nil {
		return tokenSnapshot{}
	}
	return tokenSnapshot{
		Age:            time.Since(info.ModTime()),
		TokenPerMinute: parseCodexTokenRate(path, 15*time.Minute),
	}
}

type tokenSnapshot struct {
	TokenPerMinute float64
	Age            time.Duration
}

func parseCodexTokenRate(path string, window time.Duration) float64 {
	buf, err := tailFile(path, 512*1024)
	if err != nil {
		return 0
	}

	type point struct {
		TS    time.Time
		Total int64
	}
	points := make([]point, 0, 16)
	s := bufio.NewScanner(bytes.NewReader(buf))
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		var row struct {
			Timestamp string `json:"timestamp"`
			Type      string `json:"type"`
			Payload   struct {
				Type string `json:"type"`
				Info struct {
					TotalTokenUsage struct {
						TotalTokens int64 `json:"total_tokens"`
					} `json:"total_token_usage"`
				} `json:"info"`
			} `json:"payload"`
		}
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			continue
		}
		if row.Type != "event_msg" || row.Payload.Type != "token_count" {
			continue
		}
		ts, err := time.Parse(time.RFC3339Nano, row.Timestamp)
		if err != nil {
			continue
		}
		points = append(points, point{TS: ts, Total: row.Payload.Info.TotalTokenUsage.TotalTokens})
	}
	if len(points) < 2 {
		return 0
	}

	windowStart := time.Now().Add(-window)
	filtered := points[:0]
	for _, p := range points {
		if p.TS.After(windowStart) {
			filtered = append(filtered, p)
		}
	}
	if len(filtered) < 2 {
		return 0
	}
	first := filtered[0]
	last := filtered[len(filtered)-1]
	dt := last.TS.Sub(first.TS).Minutes()
	if dt <= 0 {
		return 0
	}
	delta := last.Total - first.Total
	if delta <= 0 {
		return 0
	}
	return float64(delta) / dt
}

func latestGlobFile(glob string) string {
	matches, err := filepath.Glob(expandHome(glob))
	if err != nil || len(matches) == 0 {
		return ""
	}
	type e struct {
		path string
		mod  time.Time
	}
	entries := make([]e, 0, len(matches))
	for _, m := range matches {
		info, err := os.Stat(m)
		if err != nil || info.IsDir() {
			continue
		}
		entries = append(entries, e{path: m, mod: info.ModTime()})
	}
	if len(entries) == 0 {
		return ""
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].mod.After(entries[j].mod) })
	return entries[0].path
}

func claudeProjectKey(projectRoot string) string {
	abs := projectRoot
	if !filepath.IsAbs(abs) {
		if v, err := filepath.Abs(abs); err == nil {
			abs = v
		}
	}
	key := strings.ReplaceAll(filepath.Clean(abs), string(os.PathSeparator), "-")
	if !strings.HasPrefix(key, "-") {
		key = "-" + key
	}
	return key
}

func claudeProjectTranscriptGlob(projectRoot string) string {
	return filepath.Join("~/.claude/projects", claudeProjectKey(projectRoot), "*.jsonl")
}

func claudeWorkerTranscriptPath(projectRoot, sessionID string) string {
	return filepath.Join("~/.claude/projects", claudeProjectKey(projectRoot), sessionID+".jsonl")
}

func computeEventFingerprint(cfg Config) string {
	var b strings.Builder

	// Bead/workflow changes.
	beadsRoot := filepath.Join(cfg.ProjectRoot, ".beads")
	b.WriteString("beads:")
	b.WriteString(dirFingerprint(beadsRoot))
	b.WriteString("|")

	// Worker runtime + transcript activity changes.
	runtimeMap, _ := loadWorkerRuntimeMap(cfg.ProjectRoot)
	workerIDs := make([]string, 0, len(runtimeMap))
	for wid := range runtimeMap {
		workerIDs = append(workerIDs, wid)
	}
	sort.Strings(workerIDs)
	for _, wid := range workerIDs {
		rt := runtimeMap[wid]
		b.WriteString(wid)
		b.WriteString(":")
		b.WriteString(strings.TrimSpace(rt.LaunchedAt))
		b.WriteString(":")
		path := expandHome(strings.TrimSpace(rt.TranscriptPath))
		if path == "" {
			b.WriteString("-")
			b.WriteString("|")
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			b.WriteString(path)
			b.WriteString(":missing|")
			continue
		}
		b.WriteString(path)
		b.WriteString(":")
		b.WriteString(strconv.FormatInt(info.ModTime().UnixNano(), 10))
		b.WriteString(":")
		b.WriteString(strconv.FormatInt(info.Size(), 10))
		b.WriteString("|")
	}

	return b.String()
}

func dirFingerprint(root string) string {
	root = strings.TrimSpace(root)
	if root == "" {
		return "none"
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return "missing"
	}

	var maxMod int64
	var files int64
	var total int64
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d == nil || d.IsDir() {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return nil
		}
		files++
		total += fi.Size()
		mod := fi.ModTime().UnixNano()
		if mod > maxMod {
			maxMod = mod
		}
		return nil
	})
	return fmt.Sprintf("f=%d,s=%d,m=%d", files, total, maxMod)
}

func newUUIDv4() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return deterministicSessionID(fmt.Sprintf("%d", time.Now().UnixNano()))
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	hexID := hex.EncodeToString(b[:])
	return fmt.Sprintf("%s-%s-%s-%s-%s", hexID[0:8], hexID[8:12], hexID[12:16], hexID[16:20], hexID[20:32])
}

func deterministicSessionID(workerID string) string {
	sum := sha1.Sum([]byte("bsw-claude-session:" + workerID))
	var b [16]byte
	copy(b[:], sum[:16])
	// RFC 4122 variant + version 5 format.
	b[6] = (b[6] & 0x0f) | 0x50
	b[8] = (b[8] & 0x3f) | 0x80
	hexID := hex.EncodeToString(b[:])
	return fmt.Sprintf("%s-%s-%s-%s-%s", hexID[0:8], hexID[8:12], hexID[12:16], hexID[16:20], hexID[20:32])
}

func tailFile(path string, maxBytes int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	start := int64(0)
	if info.Size() > maxBytes {
		start = info.Size() - maxBytes
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return nil, err
	}
	return io.ReadAll(f)
}

func unixToTime(v int64) time.Time {
	if v <= 0 {
		return time.Time{}
	}
	return time.Unix(v, 0)
}

func sinceSafe(t time.Time) time.Duration {
	if t.IsZero() {
		return 0
	}
	d := time.Since(t)
	if d < 0 {
		return 0
	}
	return d
}

func shellEscape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

func shellEscapeForLine(s string) string {
	if strings.ContainsAny(s, " \t'\"$") {
		return shellEscape(s)
	}
	return s
}

func renderTemplate(input string, vars map[string]string) string {
	out := input
	for k, v := range vars {
		out = strings.ReplaceAll(out, "{"+k+"}", v)
	}
	return out
}

func expandHome(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, strings.TrimPrefix(path, "~/"))
		}
	}
	return path
}

func inferProjectRoot(start string) (string, error) {
	cur, err := filepath.Abs(start)
	if err != nil {
		return "", err
	}
	for {
		if fi, err := os.Stat(filepath.Join(cur, ".beads")); err == nil && fi.IsDir() {
			return cur, nil
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return start, nil
		}
		cur = parent
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func slug(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	v = regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(v, "-")
	v = strings.Trim(v, "-")
	if v == "" {
		return "swarm"
	}
	return v
}

func shortDur(d time.Duration) string {
	if d <= 0 {
		return "-"
	}
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	return fmt.Sprintf("%dh", int(d.Hours()))
}

func atoiSafe(v string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(v))
	return n
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func printStatusTable(rows []WorkerStatus) {
	if len(rows) == 0 {
		fmt.Println("no swarm panes found")
		return
	}
	fmt.Printf("%-16s %-4s %-8s %-12s %-7s %-14s %-8s %-9s %-6s %-8s %-10s\n", "SESSION", "PANE", "ROLE", "AGENT", "STATE", "BEAD", "PROVIDER", "MODEL", "EFFORT", "DURATION", "ACTIVITY")
	for _, r := range rows {
		bead := r.BeadID
		if bead == "" {
			bead = "-"
		}
		agent := r.AgentName
		if agent == "" {
			agent = "-"
		}
		model := r.Model
		if model == "" {
			model = "-"
		}
		effort := r.Effort
		if effort == "" {
			effort = "-"
		}
		fmt.Printf("%-16s %-4d %-8s %-12s %-7s %-14s %-8s %-9s %-6s %-8s %-10s\n",
			r.Session, r.Pane, r.Role, agent, r.State, bead, r.Provider, model, effort, shortDur(r.Duration), shortActivity(r))
	}
}

func printTickReport(cfg Config, beforeRows, afterRows []WorkerStatus, beforeBeads, afterBeads []Bead, beforeQueue, afterQueue map[string][]Bead) {
	now := time.Now().UTC().Format(time.RFC3339)
	fmt.Printf("tick %s\n", now)
	fmt.Printf("session: %s\n", cfg.Session)
	fmt.Printf("project: %s\n", cfg.ProjectRoot)
	fmt.Printf("workers before: panes=%d assigned=%d states={%s}\n", len(beforeRows), countAssignedRows(beforeRows), formatStateCounts(beforeRows))
	fmt.Printf("workers after : panes=%d assigned=%d states={%s}\n", len(afterRows), countAssignedRows(afterRows), formatStateCounts(afterRows))
	if counts, total, err := listBeadStatusCounts(cfg.ProjectRoot); err == nil {
		fmt.Printf("%s\n", formatBeadStatusLine(counts, total))
		fmt.Printf("%s\n", formatBeadStatusDetailLine(counts))
	}
	if flow, err := listWorkflowStageCounts(cfg.ProjectRoot); err == nil {
		fmt.Printf("%s\n", formatWorkflowNeedLine(flow))
		fmt.Printf("%s\n", formatWorkflowAssignedLine(flow))
	}

	assignedByRole := map[string]int{}
	for _, r := range afterRows {
		if strings.TrimSpace(r.BeadID) != "" {
			assignedByRole[r.Role]++
		}
	}
	beforeUnassigned := totalQueueCount(beforeQueue)
	afterUnassigned := totalQueueCount(afterQueue)
	fmt.Printf("queue (unassigned needs-*): %d -> %d (Δ%s)\n", beforeUnassigned, afterUnassigned, signedDelta(afterUnassigned-beforeUnassigned))
	fmt.Printf("queue tracked beads (open|in_progress): %d -> %d (Δ%s)\n", len(beforeBeads), len(afterBeads), signedDelta(len(afterBeads)-len(beforeBeads)))
	fmt.Println("queue by role:")
	for _, role := range cfg.Roles {
		qBefore := len(beforeQueue[role.Label])
		qAfter := len(afterQueue[role.Label])
		fmt.Printf("  - %-9s [%-12s] q:%3d -> %-3d (Δ%s) assigned:%d\n",
			role.Name, role.Label, qBefore, qAfter, signedDelta(qAfter-qBefore), assignedByRole[role.Name])
	}

	beforeByWorker := make(map[string]WorkerStatus, len(beforeRows))
	for _, r := range beforeRows {
		beforeByWorker[r.WorkerID] = r
	}

	rows := append([]WorkerStatus(nil), afterRows...)
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Session != rows[j].Session {
			return rows[i].Session < rows[j].Session
		}
		return rows[i].Pane < rows[j].Pane
	})

	roleMap := mapRoleConfig(cfg.Roles)
	fmt.Println("pane decisions:")
	changed := 0
	unchanged := 0
	for _, after := range rows {
		var beforePtr *WorkerStatus
		if b, ok := beforeByWorker[after.WorkerID]; ok {
			bc := b
			beforePtr = &bc
		}
		beforeState := "-"
		if beforePtr != nil {
			beforeState = paneStateSummary(*beforePtr)
		}
		afterState := paneStateSummary(after)
		decision := reduce(tickPaneDecision(beforePtr, after, roleMap[after.Role]), 100)
		marker := "="
		if beforePtr == nil || beforeState != afterState {
			marker = "Δ"
		}
		if strings.EqualFold(after.State, "blocked") {
			marker = "!"
		}
		if marker == "=" {
			unchanged++
		} else {
			changed++
		}
		fmt.Printf("  %s pane=%-2d role=%-9s agent=%-12s %s -> %s | %s\n",
			marker, after.Pane, after.Role, reduce(after.AgentName, 12), reduce(beforeState, 18), reduce(afterState, 18), decision)
	}
	fmt.Printf("decision summary: changed=%d unchanged=%d\n", changed, unchanged)
}

func printDaemonCompactReport(trigger string, rows []WorkerStatus, previous map[string]WorkerStatus) {
	ts := time.Now().Format("15:04:05")
	stateCounts := formatStateCounts(rows)
	assigned := countAssignedRows(rows)
	fmt.Printf("[%s] %s workers=%d assigned=%d states={%s}\n", ts, trigger, len(rows), assigned, stateCounts)

	ordered := append([]WorkerStatus(nil), rows...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Session != ordered[j].Session {
			return ordered[i].Session < ordered[j].Session
		}
		return ordered[i].Pane < ordered[j].Pane
	})

	changes := 0
	for _, cur := range ordered {
		prev, ok := previous[cur.WorkerID]
		if ok &&
			prev.State == cur.State &&
			strings.TrimSpace(prev.BeadID) == strings.TrimSpace(cur.BeadID) &&
			strings.TrimSpace(prev.Reason) == strings.TrimSpace(cur.Reason) {
			continue
		}
		changes++
		prevState := "-"
		prevBead := "-"
		if ok {
			prevState = prev.State
			prevBead = blankDash(prev.BeadID)
		}
		token := ""
		if cur.TokenPerMinute > 0 {
			token = fmt.Sprintf(" tok=%.0f/m", cur.TokenPerMinute)
		}
		fmt.Printf("  Δ pane=%d %-10s %s/%s -> %s/%s reason=%s%s\n",
			cur.Pane,
			shortWorkerName(cur.WorkerID),
			prevState,
			prevBead,
			cur.State,
			blankDash(cur.BeadID),
			blankDash(cur.Reason),
			token,
		)
	}
	if changes == 0 {
		fmt.Println("  = no pane changes")
	}
}

func snapshotStatusMap(rows []WorkerStatus) map[string]WorkerStatus {
	out := make(map[string]WorkerStatus, len(rows))
	for _, r := range rows {
		out[r.WorkerID] = r
	}
	return out
}

func totalQueueCount(queue map[string][]Bead) int {
	n := 0
	for _, items := range queue {
		n += len(items)
	}
	return n
}

func signedDelta(v int) string {
	if v > 0 {
		return fmt.Sprintf("+%d", v)
	}
	if v < 0 {
		return fmt.Sprintf("%d", v)
	}
	return "0"
}

func countAssignedRows(rows []WorkerStatus) int {
	n := 0
	for _, r := range rows {
		if strings.TrimSpace(r.BeadID) != "" {
			n++
		}
	}
	return n
}

func formatStateCounts(rows []WorkerStatus) string {
	counts := map[string]int{}
	for _, r := range rows {
		counts[r.State]++
	}
	order := []string{"assigned", "busy", "waiting", "ready", "idle", "blocked", "shell", "error"}
	parts := make([]string, 0, len(order)+2)
	for _, s := range order {
		if counts[s] > 0 {
			parts = append(parts, fmt.Sprintf("%s=%d", s, counts[s]))
			delete(counts, s)
		}
	}
	if len(counts) > 0 {
		extra := make([]string, 0, len(counts))
		for k := range counts {
			extra = append(extra, k)
		}
		sort.Strings(extra)
		for _, k := range extra {
			parts = append(parts, fmt.Sprintf("%s=%d", k, counts[k]))
		}
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, " ")
}

func paneStateSummary(s WorkerStatus) string {
	bead := s.BeadID
	if bead == "" {
		bead = "-"
	}
	return fmt.Sprintf("%s/%s", s.State, bead)
}

func tickPaneDecision(before *WorkerStatus, after WorkerStatus, role RoleConfig) string {
	afterBead := strings.TrimSpace(after.BeadID)
	if after.State == "shell" {
		return "skip: agent-not-running"
	}
	if before == nil {
		if afterBead != "" {
			return "new-worker: already assigned " + afterBead
		}
		return "new-worker: no assignment"
	}

	beforeBead := strings.TrimSpace(before.BeadID)
	switch {
	case beforeBead == "" && after.State == "assigned" && afterBead != "":
		return fmt.Sprintf("assigned bead %s from queue %s", afterBead, role.Label)
	case beforeBead != "" && afterBead == beforeBead && after.Reason == "nudge-sent":
		return "nudged assigned worker for progress"
	case beforeBead != "" && afterBead == beforeBead:
		return fmt.Sprintf("kept assignment (%s)", after.State)
	case beforeBead == "" && afterBead == "" && after.State == "idle" && after.Reason == "queue-empty":
		return fmt.Sprintf("no queued work for %s", role.Label)
	case beforeBead == "" && afterBead == "":
		return "no assignment"
	case beforeBead != "" && afterBead == "":
		return fmt.Sprintf("assignment cleared externally (%s)", beforeBead)
	case beforeBead == "" && afterBead != "":
		return fmt.Sprintf("assignment appeared (%s)", afterBead)
	case beforeBead != afterBead:
		return fmt.Sprintf("assignment changed %s -> %s", beforeBead, afterBead)
	default:
		if strings.TrimSpace(after.Reason) != "" {
			return after.Reason
		}
		return "no-op"
	}
}

func shortActivity(r WorkerStatus) string {
	if r.TokenPerMinute > 0 {
		return fmt.Sprintf("%.0f tok/m", r.TokenPerMinute)
	}
	if r.ActivityAge > 0 {
		return shortDur(r.ActivityAge)
	}
	return "-"
}

// ---- TUI ----

type tickMsg time.Time

type dataMsg struct {
	Rows           []WorkerStatus
	LifecycleRows  []LifecycleBeadRow
	BeadCounts     map[string]int
	BeadTotal      int
	WorkflowStages WorkflowStageCounts
	Lifecycle      LifecycleCounts
	PlanMeta       SwarmMeta
	FlowSpec       FlowSpec
	FlowCurrent    string
	Err            error
}

type tuiModel struct {
	cfg             Config
	refresh         time.Duration
	tab             int
	rows            []WorkerStatus
	lifecycleRows   []LifecycleBeadRow
	beadCounts      map[string]int
	beadTotal       int
	flowStages      WorkflowStageCounts
	lifecycle       LifecycleCounts
	planMeta        SwarmMeta
	flowSpec        FlowSpec
	flowCurrent     string
	tickLog         []string
	showTickLog     bool
	cursor          int
	lifecycleCursor int
	expandedHistory map[string]bool
	err             error
	zoomTarget      *WorkerStatus
	lastUpdated     time.Time
	width           int
	height          int
}

func newTUIModel(cfg Config, refresh time.Duration) tuiModel {
	return tuiModel{
		cfg:             cfg,
		refresh:         refresh,
		tab:             0,
		rows:            []WorkerStatus{},
		lifecycleRows:   []LifecycleBeadRow{},
		beadCounts:      map[string]int{},
		tickLog:         []string{},
		showTickLog:     true,
		expandedHistory: map[string]bool{},
	}
}

func (m tuiModel) Init() tea.Cmd {
	return tea.Batch(m.fetchCmd(), m.tickCmd())
}

func (m tuiModel) tickCmd() tea.Cmd {
	return tea.Tick(m.refresh, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (m tuiModel) fetchCmd() tea.Cmd {
	return func() tea.Msg {
		// TUI is project/session scoped: show workers for this configured swarm only.
		rows, err := collectStatuses(m.cfg, false)
		if err != nil {
			return dataMsg{Rows: rows, Err: err}
		}
		lifecycleRows, _ := listLifecycleBeadRows(m.cfg.ProjectRoot)
		counts, total, _ := listBeadStatusCounts(m.cfg.ProjectRoot)
		flow, _ := listWorkflowStageCounts(m.cfg.ProjectRoot)
		lifecycle, _ := lifecycleCountsFromJSONL(m.cfg.ProjectRoot)
		meta, _ := loadSwarmMeta(m.cfg.ProjectRoot)
		flowSpec, _ := loadFlowSpec(m.cfg.ProjectRoot)
		flowCurrent := inferCurrentFlowNode(flowSpec, flow, rows)
		return dataMsg{
			Rows:           rows,
			LifecycleRows:  lifecycleRows,
			BeadCounts:     counts,
			BeadTotal:      total,
			WorkflowStages: flow,
			Lifecycle:      lifecycle,
			PlanMeta:       meta,
			FlowSpec:       flowSpec,
			FlowCurrent:    flowCurrent,
			Err:            nil,
		}
	}
}

func (m tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "r":
			return m, m.fetchCmd()
		case "t":
			m.showTickLog = !m.showTickLog
		case "tab":
			m.tab = (m.tab + 1) % 2
		case "up", "k":
			if m.tab == 0 {
				if m.cursor > 0 {
					m.cursor--
				}
			} else {
				if m.lifecycleCursor > 0 {
					m.lifecycleCursor--
				}
			}
		case "down", "j":
			if m.tab == 0 {
				if m.cursor < len(m.rows)-1 {
					m.cursor++
				}
			} else {
				if m.lifecycleCursor < len(m.lifecycleRows)-1 {
					m.lifecycleCursor++
				}
			}
		case "enter":
			if m.tab == 0 {
				if len(m.rows) > 0 && m.cursor < len(m.rows) {
					sel := m.rows[m.cursor]
					m.zoomTarget = &sel
					return m, tea.Quit
				}
			} else {
				if len(m.lifecycleRows) > 0 && m.lifecycleCursor < len(m.lifecycleRows) {
					id := m.lifecycleRows[m.lifecycleCursor].ID
					m.expandedHistory[id] = !m.expandedHistory[id]
				}
			}
		case "z":
			if m.tab == 0 && len(m.rows) > 0 && m.cursor < len(m.rows) {
				sel := m.rows[m.cursor]
				m.zoomTarget = &sel
				return m, tea.Quit
			}
		}
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case tickMsg:
		return m, tea.Batch(m.fetchCmd(), m.tickCmd())
	case dataMsg:
		m.err = msg.Err
		if msg.Err == nil {
			m.tickLog = appendTickLogEntries(m.tickLog, buildTickLogLines(m.rows, msg.Rows))
			m.rows = msg.Rows
			m.lifecycleRows = msg.LifecycleRows
			if msg.BeadCounts != nil {
				m.beadCounts = msg.BeadCounts
			}
			m.beadTotal = msg.BeadTotal
			m.flowStages = msg.WorkflowStages
			m.lifecycle = msg.Lifecycle
			m.planMeta = msg.PlanMeta
			m.flowSpec = msg.FlowSpec
			m.flowCurrent = msg.FlowCurrent
			if m.cursor >= len(m.rows) {
				m.cursor = max(0, len(m.rows)-1)
			}
			if m.lifecycleCursor >= len(m.lifecycleRows) {
				m.lifecycleCursor = max(0, len(m.lifecycleRows)-1)
			}
			m.lastUpdated = time.Now()
		}
	}
	return m, nil
}

func (m tuiModel) View() string {
	if m.tab == 1 {
		return m.viewLifecycle()
	}
	return m.viewSessions()
}

func (m tuiModel) viewSessions() string {
	headerStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("252"))
	mutedStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("244"))

	width := m.width
	if width <= 0 {
		width = 140
	}
	height := m.height
	if height <= 0 {
		height = 40
	}
	cols := fitTUIColumns(width, maxSessionCellWidth(m.rows), maxPaneNameCellWidth(m.rows))
	// Keep tick log compact so worker table remains primary on regular terminal heights.
	logHeight := clamp(max(3, height/5), 3, 8)
	if !m.showTickLog {
		logHeight = 0
	}

	var b strings.Builder
	b.WriteString(renderTabStrip(0) + "\n")

	if m.err != nil {
		b.WriteString(mutedStyle.Render("error: "+m.err.Error()) + "\n")
	}
	statusLines := renderSystemStatusBlock(width, m.flowStages, m.lifecycle, m.beadCounts, m.beadTotal, m.planMeta, m.rows)
	b.WriteString(headerStyle.Render(statusLines[0]) + "\n")
	b.WriteString(mutedStyle.Render(strings.Repeat("-", min(70, max(20, width-1)))) + "\n")
	for _, ln := range statusLines[1:] {
		b.WriteString(mutedStyle.Render(ln) + "\n")
	}

	header := strings.Join([]string{
		padCell("SESSION", cols.Session),
		padCell("PANE", cols.Pane),
		padCell("PANE_NAME", cols.PaneName),
		padCell("STATE", cols.State),
		padCell("BEAD", cols.Bead),
		padCell("PROVIDER", cols.Provider),
		padCell("MODEL", cols.Model),
		padCell("EFFORT", cols.Effort),
		padCell("DUR", cols.Duration),
		padCell("ACTIVITY", cols.Activity),
	}, " ")
	b.WriteString(headerStyle.Render(header) + "\n")
	b.WriteString(mutedStyle.Render(strings.Repeat("-", visibleLen(header))) + "\n")

	// Reserve space for fixed tick log section at bottom.
	staticTop := 2 + len(statusLines) + 3 // title+tab + status header/rule/lines + table header+rule
	footerLines := 2
	maxRows := height - staticTop - logHeight - footerLines
	if maxRows < 1 {
		maxRows = 1
	}
	start := 0
	if m.cursor >= maxRows {
		start = m.cursor - maxRows + 1
	}
	if start < 0 {
		start = 0
	}
	end := min(len(m.rows), start+maxRows)

	if len(m.rows) == 0 {
		b.WriteString(mutedStyle.Render("(no matching panes)") + "\n")
	} else {
		for i := start; i < end; i++ {
			r := m.rows[i]
			prefix := "  "
			if i == m.cursor {
				prefix = "> "
			}
			bead := r.BeadID
			if bead == "" {
				bead = "-"
			}
			line := strings.Join([]string{
				padCell(r.Session, cols.Session),
				padCell(strconv.Itoa(r.Pane), cols.Pane),
				padCell(shortWorkerName(r.WorkerID), cols.PaneName),
				padCell(r.State, cols.State),
				padCell(bead, cols.Bead),
				padCell(r.Provider, cols.Provider),
				padCell(r.Model, cols.Model),
				padCell(r.Effort, cols.Effort),
				padCell(shortDur(r.Duration), cols.Duration),
				padCell(r.Activity, cols.Activity),
			}, " ")
			rowTheme := roleThemeFor(r.Role)
			square := lipgloss.NewStyle().Foreground(rowTheme.RowBG).Render("■")
			b.WriteString(prefix + square + " " + line + "\n")
		}
		if end < len(m.rows) {
			b.WriteString(mutedStyle.Render(fmt.Sprintf("... +%d more rows (use j/k)", len(m.rows)-end)) + "\n")
		}
	}

	b.WriteString("\n")
	b.WriteString(renderRoleLegendLine() + "\n")
	b.WriteString(renderKeysLine(width, "tab switch view, up/down (j/k) move, Enter/z zoom, r refresh, t toggle-log, q quit") + "\n")
	if m.showTickLog {
		b.WriteString("\n")
		b.WriteString(renderTickLogBlock(width, visibleLen(header), m.tickLog, logHeight-2))
	}
	if !m.lastUpdated.IsZero() {
		b.WriteString("\n" + mutedStyle.Render("updated: "+m.lastUpdated.Format("15:04:05")) + "\n")
	}
	return b.String()
}

func (m tuiModel) viewLifecycle() string {
	headerStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("252"))
	mutedStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("244"))

	width := m.width
	if width <= 0 {
		width = 140
	}
	height := m.height
	if height <= 0 {
		height = 40
	}
	logHeight := clamp(max(3, height/6), 3, 8)
	if !m.showTickLog {
		logHeight = 0
	}

	var b strings.Builder
	b.WriteString(renderTabStrip(1) + "\n")
	if m.err != nil {
		b.WriteString(mutedStyle.Render("error: "+m.err.Error()) + "\n")
	}
	statusLines := renderSystemStatusBlock(width, m.flowStages, m.lifecycle, m.beadCounts, m.beadTotal, m.planMeta, m.rows)
	b.WriteString(headerStyle.Render(statusLines[0]) + "\n")
	b.WriteString(mutedStyle.Render(strings.Repeat("-", min(70, max(20, width-1)))) + "\n")
	for _, ln := range statusLines[1:] {
		b.WriteString(mutedStyle.Render(ln) + "\n")
	}

	tlWidth := 2
	for _, r := range m.lifecycleRows {
		if n := len(r.Timeline); n > tlWidth {
			tlWidth = n
		}
	}
	if tlWidth > 24 {
		tlWidth = 24
	}
	header := fmt.Sprintf("%-*s BEAD         STAGE  STATUS       CNT         LAST_STATE         ASSIGNEE", tlWidth, "TL")
	b.WriteString(headerStyle.Render(reduce(header, max(20, width-1))) + "\n")
	b.WriteString(mutedStyle.Render(strings.Repeat("-", min(visibleLen(header), width-1))) + "\n")

	staticTop := 2 + len(statusLines) + 3
	footerLines := 2
	maxRows := height - staticTop - footerLines - logHeight - 3
	if maxRows < 1 {
		maxRows = 1
	}
	start := 0
	if m.lifecycleCursor >= maxRows {
		start = m.lifecycleCursor - maxRows + 1
	}
	if start < 0 {
		start = 0
	}
	end := min(len(m.lifecycleRows), start+maxRows)

	if len(m.lifecycleRows) == 0 {
		b.WriteString(mutedStyle.Render("(no active beads)") + "\n")
	} else {
		for i := start; i < end; i++ {
			r := m.lifecycleRows[i]
			prefix := "  "
			if i == m.lifecycleCursor {
				prefix = "> "
			}
			cnt := fmt.Sprintf("%d/%d/%d/%d/%d", r.ImplDone, r.ProofFailed, r.ProofPassed, r.ReviewFailed, r.ReviewPassed)
			line := fmt.Sprintf("%s %-12s %-6s %-12s %-11s %-18s %-24s",
				renderBeadTimelineCell(r.Timeline, tlWidth), r.ID, r.Stage, r.Status, cnt, reduce(r.HistoryPreview, 18), reduce(r.Assignee, 24))
			line = prefix + line
			b.WriteString(line + "\n")
			if m.expandedHistory[r.ID] {
				title := strings.TrimSpace(r.Title)
				if title == "" {
					title = "-"
				}
				b.WriteString(mutedStyle.Render("    title: "+reduce(title, max(20, width-8))) + "\n")
				if len(r.History) == 0 {
					b.WriteString(mutedStyle.Render("    (no STATE history)") + "\n")
				} else {
					for _, h := range r.History {
						b.WriteString(mutedStyle.Render("    "+reduce(h, max(20, width-6))) + "\n")
					}
				}
			}
		}
		if end < len(m.lifecycleRows) {
			b.WriteString(mutedStyle.Render(fmt.Sprintf("... +%d more beads (use j/k)", len(m.lifecycleRows)-end)) + "\n")
		}
	}
	b.WriteString("\n")
	legend := "legend: I=impl_done PF=proof_failed PP=proof_passed RF=review_failed RP=review_passed"
	b.WriteString(mutedStyle.Render(reduce(legend, max(20, width-1))) + "\n")
	b.WriteString(renderTimelineLegendLine() + "\n")
	b.WriteString(renderKeysLine(width, "tab switch view, up/down (j/k) move, Enter toggle history, r refresh, t toggle-log, q quit") + "\n")
	if m.showTickLog {
		b.WriteString("\n")
		b.WriteString(renderTickLogBlock(width, visibleLen(header), m.tickLog, logHeight))
	}
	if !m.lastUpdated.IsZero() {
		b.WriteString("\n" + mutedStyle.Render("updated: "+m.lastUpdated.Format("15:04:05")) + "\n")
	}
	return b.String()
}

func (m tuiModel) viewPlan() string {
	headerStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("252"))
	mutedStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	width := m.width
	if width <= 0 {
		width = 140
	}
	var b strings.Builder
	b.WriteString(renderTabStrip(2) + "\n")
	if m.err != nil {
		b.WriteString(mutedStyle.Render("error: "+m.err.Error()) + "\n")
	}
	statusLines := renderSystemStatusBlock(width, m.flowStages, m.lifecycle, m.beadCounts, m.beadTotal, m.planMeta, m.rows)
	b.WriteString(headerStyle.Render(statusLines[0]) + "\n")
	b.WriteString(mutedStyle.Render(strings.Repeat("-", min(70, max(20, width-1)))) + "\n")
	for _, ln := range statusLines[1:] {
		b.WriteString(mutedStyle.Render(ln) + "\n")
	}
	planFile := strings.TrimSpace(m.planMeta.PlanFile)
	if planFile == "" {
		planFile = "-"
	}
	b.WriteString(headerStyle.Render("plan file: ") + reduce(planFile, max(20, width-12)) + "\n")
	if len(m.planMeta.Topics) > 0 {
		b.WriteString(headerStyle.Render("topics: ") + reduce(strings.Join(m.planMeta.Topics, ", "), max(20, width-10)) + "\n")
	} else {
		b.WriteString(headerStyle.Render("topics: ") + "-\n")
	}
	b.WriteString("\n")
	b.WriteString(renderRoleLegendLine() + "\n")
	b.WriteString(renderKeysLine(width, "tab switch view, r refresh, t toggle-log, q quit") + "\n")
	var planRow *WorkerStatus
	for i := range m.rows {
		if strings.EqualFold(m.rows[i].Role, "plan-review") {
			planRow = &m.rows[i]
			break
		}
	}
	b.WriteString("\n" + headerStyle.Render("plan reviewer") + "\n")
	b.WriteString(mutedStyle.Render(strings.Repeat("-", min(60, max(20, width-1)))) + "\n")
	if planRow == nil {
		b.WriteString(mutedStyle.Render("no plan-review pane") + "\n")
	} else {
		t := roleThemeFor(planRow.Role)
		rowStyle := lipgloss.NewStyle().Background(t.RowBG).Foreground(t.RowFG)
		line := fmt.Sprintf("pane=%d agent=%s state=%s provider=%s model=%s effort=%s activity=%s",
			planRow.Pane, planRow.AgentName, planRow.State, planRow.Provider, blankDash(planRow.Model), blankDash(planRow.Effort), blankDash(planRow.Activity))
		b.WriteString(rowStyle.Render(reduce(line, max(20, width-2))) + "\n")
	}
	if m.showTickLog {
		b.WriteString("\n")
		b.WriteString(renderTickLogBlock(width, 60, m.tickLog, 5))
	}
	if !m.lastUpdated.IsZero() {
		b.WriteString("\n" + mutedStyle.Render("updated: "+m.lastUpdated.Format("15:04:05")) + "\n")
	}
	return b.String()
}

func (m tuiModel) viewFlow() string {
	headerStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("252"))
	mutedStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	activeStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("230")).Background(lipgloss.Color("62"))
	width := m.width
	if width <= 0 {
		width = 140
	}
	var b strings.Builder
	b.WriteString(renderTabStrip(3) + "\n")
	if m.err != nil {
		b.WriteString(mutedStyle.Render("error: "+m.err.Error()) + "\n")
	}
	statusLines := renderSystemStatusBlock(width, m.flowStages, m.lifecycle, m.beadCounts, m.beadTotal, m.planMeta, m.rows)
	b.WriteString(headerStyle.Render(statusLines[0]) + "\n")
	b.WriteString(mutedStyle.Render(sectionRule(width)) + "\n")
	for _, ln := range statusLines[1:] {
		b.WriteString(mutedStyle.Render(ln) + "\n")
	}
	b.WriteString(mutedStyle.Render(sectionRule(width)) + "\n")

	current := strings.TrimSpace(m.flowCurrent)
	if current == "" {
		current = "-"
	}
	start := strings.TrimSpace(m.flowSpec.Start)
	if start == "" {
		start = "-"
	}
	b.WriteString(headerStyle.Render("start: ") + start + "\n")
	if current != "-" {
		b.WriteString(activeStyle.Render(" current: "+current+" ") + "\n")
	} else {
		b.WriteString(headerStyle.Render("current: ") + "-\n")
	}

	b.WriteString("\n" + headerStyle.Render("state machine") + "\n")
	b.WriteString(mutedStyle.Render(sectionRule(width)) + "\n")
	for _, line := range renderFlowDAGLines(m.flowSpec, m.flowCurrent, width) {
		b.WriteString(line + "\n")
	}
	b.WriteString("\n")
	b.WriteString(renderRoleLegendLine() + "\n")
	b.WriteString(renderKeysLine(width, "tab switch view, r refresh, t toggle-log, q quit") + "\n")
	if m.showTickLog {
		b.WriteString("\n")
		b.WriteString(renderTickLogBlock(width, 70, m.tickLog, 5))
	}
	if !m.lastUpdated.IsZero() {
		b.WriteString("\n" + mutedStyle.Render("updated: "+m.lastUpdated.Format("15:04:05")) + "\n")
	}
	return b.String()
}

func buildTickLogLines(beforeRows, afterRows []WorkerStatus) []string {
	ts := time.Now().Format("15:04:05")
	lines := []string{}
	lines = append(lines, fmt.Sprintf("%s workers=%d assigned=%d states={%s}",
		ts, len(afterRows), countAssignedRows(afterRows), formatStateCounts(afterRows)))
	if len(beforeRows) == 0 && len(afterRows) > 0 {
		lines = append(lines, fmt.Sprintf("%s init rows=%d", ts, len(afterRows)))
		return lines
	}

	beforeByID := make(map[string]WorkerStatus, len(beforeRows))
	for _, r := range beforeRows {
		beforeByID[r.WorkerID] = r
	}
	afterByID := make(map[string]WorkerStatus, len(afterRows))
	for _, r := range afterRows {
		afterByID[r.WorkerID] = r
	}

	changed := 0
	keys := make([]string, 0, len(afterByID))
	for k := range afterByID {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		after := afterByID[k]
		before, ok := beforeByID[k]
		if !ok {
			lines = append(lines, fmt.Sprintf("%s + pane=%d name=%s role=%s state=%s bead=%s",
				ts, after.Pane, shortWorkerName(after.WorkerID), after.Role, after.State, blankDash(after.BeadID)))
			changed++
			continue
		}
		if before.State != after.State || strings.TrimSpace(before.BeadID) != strings.TrimSpace(after.BeadID) {
			lines = append(lines, fmt.Sprintf("%s Δ pane=%d name=%s %s/%s -> %s/%s",
				ts, after.Pane, shortWorkerName(after.WorkerID), before.State, blankDash(before.BeadID), after.State, blankDash(after.BeadID)))
			changed++
		}
	}
	for k, before := range beforeByID {
		if _, ok := afterByID[k]; !ok {
			lines = append(lines, fmt.Sprintf("%s - pane=%d name=%s role=%s removed",
				ts, before.Pane, shortWorkerName(before.WorkerID), before.Role))
			changed++
		}
	}
	if changed == 0 {
		lines = append(lines, fmt.Sprintf("%s no pane changes", ts))
	}
	return lines
}

func appendTickLogEntries(log []string, entries []string) []string {
	if len(entries) == 0 {
		return log
	}
	out := append(log, entries...)
	const maxKeep = 400
	if len(out) > maxKeep {
		out = out[len(out)-maxKeep:]
	}
	return out
}

func lastNLogLines(lines []string, n int) []string {
	if n <= 0 || len(lines) == 0 {
		return nil
	}
	if len(lines) <= n {
		return lines
	}
	return lines[len(lines)-n:]
}

func blankDash(v string) string {
	if strings.TrimSpace(v) == "" {
		return "-"
	}
	return strings.TrimSpace(v)
}

func shortWorkerName(workerID string) string {
	s := strings.TrimSpace(workerID)
	if s == "" {
		return "-"
	}
	parts := strings.Split(s, ":")
	if len(parts) >= 3 {
		return parts[len(parts)-2] + ":" + parts[len(parts)-1]
	}
	return s
}

type tuiColumns struct {
	Session  int
	Pane     int
	PaneName int
	Agent    int
	State    int
	Bead     int
	Provider int
	Model    int
	Effort   int
	Duration int
	Activity int
}

func fitTUIColumns(total int, minSession int, minPaneName int) tuiColumns {
	if total < 80 {
		total = 80
	}
	cols := tuiColumns{
		Pane:     4,
		PaneName: 14,
		Agent:    0,
		State:    8,
		Provider: 6,
		Effort:   6,
		Duration: 6,
	}
	if minPaneName > cols.PaneName {
		cols.PaneName = minPaneName
	}
	fixed := cols.Pane + cols.PaneName + cols.State + cols.Provider + cols.Effort + cols.Duration
	remaining := total - fixed - 16
	if remaining < 40 {
		remaining = 40
	}
	// Prioritize full session visibility over model/activity when space is tight.
	cols.Session = clamp(remaining*40/100, 16, 64)
	if minSession > cols.Session {
		cols.Session = minSession
	}
	cols.Bead = clamp(remaining*16/100, 8, 20)
	cols.Model = clamp(remaining*16/100, 8, 18)
	cols.Activity = remaining - cols.Session - cols.Bead - cols.Model
	if cols.Activity < 10 {
		need := 10 - cols.Activity
		take := min(need, cols.Model-8)
		cols.Model -= take
		need -= take
		take = min(need, cols.Bead-8)
		cols.Bead -= take
		need -= take
		take = min(need, cols.Session-16)
		cols.Session -= take
		cols.Activity = 10
	}
	return cols
}

func maxSessionCellWidth(rows []WorkerStatus) int {
	w := visibleLen("SESSION")
	for _, r := range rows {
		w = max(w, visibleLen(strings.TrimSpace(r.Session)))
	}
	return w
}

func maxPaneNameCellWidth(rows []WorkerStatus) int {
	w := visibleLen("PANE_NAME")
	for _, r := range rows {
		w = max(w, visibleLen(shortWorkerName(r.WorkerID)))
	}
	return w
}

func padCell(s string, w int) string {
	if w <= 1 {
		return ""
	}
	s = reduce(s, w)
	r := []rune(s)
	if len(r) >= w {
		return s
	}
	return s + strings.Repeat(" ", w-len(r))
}

func visibleLen(s string) int {
	return len([]rune(s))
}

func reduce(s string, n int) string {
	s = strings.TrimSpace(s)
	if len([]rune(s)) <= n {
		return s
	}
	if n <= 1 {
		return string([]rune(s)[:n])
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}
