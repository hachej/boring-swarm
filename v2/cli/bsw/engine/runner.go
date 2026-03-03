package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"boring-swarm/v2/cli/bsw/agent"
	"boring-swarm/v2/cli/bsw/beads"
	"boring-swarm/v2/cli/bsw/dsl"
	"boring-swarm/v2/cli/bsw/logscan"
	"boring-swarm/v2/cli/bsw/process"
	"boring-swarm/v2/cli/bsw/status"
)

type RunOptions struct {
	ProjectRoot  string
	FlowPath     string
	Mode         string
	Actor        string
	PollInterval time.Duration
}

type Runner struct {
	spec         *dsl.FlowSpec
	specPath     string
	projectRoot  string
	actor        string
	runID        string
	pollInterval time.Duration
	emitter      *Emitter
	client       beads.Client
	registry     process.Registry
	manager      process.Manager
	cursors      CursorStore
	attempts     AttemptStore
	attention    status.AttentionStore
	timeout      time.Duration
}

func Run(ctx context.Context, opts RunOptions) error {
	if opts.Mode == "" {
		opts.Mode = "oneshot"
	}
	if opts.Mode != "oneshot" && opts.Mode != "service" {
		return fmt.Errorf("invalid mode %q; use oneshot or service", opts.Mode)
	}
	if opts.PollInterval <= 0 {
		opts.PollInterval = 2 * time.Second
	}

	spec, err := dsl.ParseFile(opts.FlowPath)
	if err != nil {
		return err
	}
	timeout, err := spec.TimeoutDuration()
	if err != nil {
		return err
	}
	if strings.TrimSpace(spec.Name) == "" {
		return fmt.Errorf("flow name is required")
	}

	r := &Runner{
		spec:         spec,
		specPath:     opts.FlowPath,
		projectRoot:  opts.ProjectRoot,
		actor:        opts.Actor,
		runID:        NewRunID(),
		pollInterval: opts.PollInterval,
		client:       beads.Client{Workdir: opts.ProjectRoot, Actor: opts.Actor},
		registry:     process.NewRegistry(opts.ProjectRoot),
		manager:      process.NewManager(opts.ProjectRoot),
		cursors:      NewCursorStore(opts.ProjectRoot),
		attempts:     NewAttemptStore(opts.ProjectRoot),
		attention:    status.NewAttentionStore(opts.ProjectRoot),
		timeout:      timeout,
	}

	if err := r.ensureRuntimeDirs(); err != nil {
		return err
	}

	releaseService := func() {}
	if opts.Mode == "service" {
		release, err := acquireServiceProcess(opts.ProjectRoot, spec.Name, r.runID, os.Getpid())
		if err != nil {
			return err
		}
		releaseService = release
	}
	defer releaseService()

	emitter, err := NewEmitter(opts.ProjectRoot, spec.Name, r.runID)
	if err != nil {
		return err
	}
	r.emitter = emitter
	defer r.emitter.Close()

	startedAt := time.Now().UTC().Format(time.RFC3339)
	if err := SaveRunState(opts.ProjectRoot, RunState{
		RunID:     r.runID,
		Flow:      opts.FlowPath,
		FlowName:  spec.Name,
		Mode:      opts.Mode,
		StartedAt: startedAt,
		PID:       os.Getpid(),
		Status:    "running",
	}); err != nil {
		return err
	}

	finalStatus := "completed"
	defer func() {
		_ = SaveRunState(opts.ProjectRoot, RunState{
			RunID:     r.runID,
			Flow:      opts.FlowPath,
			FlowName:  spec.Name,
			Mode:      opts.Mode,
			StartedAt: startedAt,
			PID:       os.Getpid(),
			Status:    finalStatus,
		})
	}()

	for {
		select {
		case <-ctx.Done():
			finalStatus = "stopped"
			r.stopAllWorkers(context.Background())
			return ctx.Err()
		default:
		}

		if stopRequested(opts.ProjectRoot) {
			r.stopAllWorkers(context.Background())
			_ = os.Remove(stopSignalPath(opts.ProjectRoot))
			finalStatus = "stopped"
			return nil
		}

		queueCount, activeWorkers, cycleErr := r.cycle(ctx)
		if cycleErr != nil {
			finalStatus = "error"
			return cycleErr
		}

		if opts.Mode == "oneshot" && queueCount == 0 && activeWorkers == 0 {
			finalStatus = "completed"
			return nil
		}

		t := time.NewTimer(r.pollInterval)
		select {
		case <-ctx.Done():
			t.Stop()
			finalStatus = "stopped"
			r.stopAllWorkers(context.Background())
			return ctx.Err()
		case <-t.C:
		}
	}
}

func (r *Runner) ensureRuntimeDirs() error {
	dirs := []string{
		filepath.Join(r.projectRoot, ".bsw"),
		filepath.Join(r.projectRoot, ".bsw", "agents"),
		filepath.Join(r.projectRoot, ".bsw", "cursors"),
		filepath.Join(r.projectRoot, ".bsw", "logs"),
		filepath.Join(r.projectRoot, ".bsw", "runtime"),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	_ = os.Remove(stopSignalPath(r.projectRoot))
	return nil
}

func stopSignalPath(projectRoot string) string {
	return filepath.Join(projectRoot, ".bsw", "stop.signal")
}

func stopRequested(projectRoot string) bool {
	_, err := os.Stat(stopSignalPath(projectRoot))
	return err == nil
}

func (r *Runner) cycle(ctx context.Context) (int, int, error) {
	runtimes, err := r.registry.LoadAll()
	if err != nil {
		return 0, 0, err
	}
	byBead := map[string]process.WorkerRuntime{}

	now := time.Now().UTC()
	sort.Slice(runtimes, func(i, j int) bool { return runtimes[i].BeadID < runtimes[j].BeadID })
	for _, existing := range runtimes {
		if strings.TrimSpace(existing.SourceLabel) != strings.TrimSpace(r.spec.Source.Label) {
			continue
		}
		rt, err := r.manager.Refresh(existing, now)
		if err != nil {
			r.emitter.Emit(Event{Event: "worker_refresh_error", RunID: r.runID, BeadID: existing.BeadID, Details: err.Error()})
			// Keep the existing runtime in memory so one bad refresh does not
			// fan out into orphaned-assignment noise on every cycle.
			fallback := existing
			if process.IsAlive(fallback.PID) {
				if strings.TrimSpace(fallback.ActivityState) == "" {
					fallback.ActivityState = string(agent.StateActive)
				}
			} else {
				fallback.ActivityState = string(agent.StateExited)
			}
			byBead[fallback.BeadID] = fallback
			continue
		}
		if err := r.registry.Save(rt); err != nil {
			return 0, 0, err
		}
		byBead[rt.BeadID] = rt

		state := strings.TrimSpace(rt.ActivityState)
		if state == "waiting_input" {
			if r.upsertAttention(status.AttentionItem{BeadID: rt.BeadID, Reason: "waiting_input", SuggestedAction: "send_mail_then_ping", Details: "provider requested user input", At: now.Format(time.RFC3339)}) {
				r.emitter.Emit(Event{Event: "attention", RunID: r.runID, BeadID: rt.BeadID, Reason: "waiting_input", SuggestedAction: "send_mail_then_ping"})
			}
		} else {
			_ = r.attention.Clear(rt.BeadID, "waiting_input")
		}

		if process.IsAlive(rt.PID) && state != "waiting_input" {
			last := process.ParseTS(rt.LastProgressTS)
			if last.IsZero() {
				last = process.ParseTS(rt.StartedAt)
			}
			if !last.IsZero() && now.Sub(last) > r.timeout {
				if r.upsertAttention(status.AttentionItem{BeadID: rt.BeadID, Reason: "stuck_no_progress", SuggestedAction: "inspect_resume_command_or_kill", Details: "timeout exceeded without progress", At: now.Format(time.RFC3339)}) {
					r.emitter.Emit(Event{Event: "attention", RunID: r.runID, BeadID: rt.BeadID, Reason: "stuck_no_progress", SuggestedAction: "inspect_resume_command_or_kill"})
				}
			} else {
				_ = r.attention.Clear(rt.BeadID, "stuck_no_progress")
			}
		}

		if !process.IsAlive(rt.PID) {
			_ = r.attention.Upsert(status.AttentionItem{BeadID: rt.BeadID, Reason: "orphaned_assignment", SuggestedAction: "inspect_and_requeue", Details: "runtime process exited", At: now.Format(time.RFC3339)})
		} else {
			_ = r.attention.Clear(rt.BeadID, "orphaned_assignment")
		}
	}

	if err := r.processStateComments(ctx, byBead); err != nil {
		return 0, 0, err
	}

	// Reload because processStateComments may have deleted runtime entries.
	runtimes, _ = r.registry.LoadAll()
	byBead = map[string]process.WorkerRuntime{}
	activeWorkers := 0
	for _, rt := range runtimes {
		if strings.TrimSpace(rt.SourceLabel) != strings.TrimSpace(r.spec.Source.Label) {
			continue
		}
		byBead[rt.BeadID] = rt
		if process.IsAlive(rt.PID) {
			activeWorkers++
		}
	}

	queueBeads, err := r.client.ListByLabel(ctx, r.spec.Source.Label)
	if err != nil {
		return 0, 0, err
	}

	for _, issue := range queueBeads {
		assignee := strings.TrimSpace(issue.Assignee)
		if assignee == "" {
			continue
		}
		if _, ok := byBead[issue.ID]; ok {
			continue
		}

		if r.upsertAttention(status.AttentionItem{BeadID: issue.ID, Reason: "orphaned_assignment", SuggestedAction: "reconcile_and_clear_stale_claim", Details: "bead assigned but no local runtime registry", At: now.Format(time.RFC3339)}) {
			r.emitter.Emit(Event{Event: "attention", RunID: r.runID, BeadID: issue.ID, Reason: "orphaned_assignment", SuggestedAction: "reconcile_and_clear_stale_claim"})
		}

		if err := r.client.ClearAssigneeIfMatch(ctx, issue.ID, assignee, r.actor); err != nil {
			r.emitter.Emit(Event{Event: "reconcile_error", RunID: r.runID, BeadID: issue.ID, Agent: assignee, Details: err.Error()})
			continue
		}
		_ = r.attention.Clear(issue.ID, "orphaned_assignment")
		r.emitter.Emit(Event{Event: "requeue", RunID: r.runID, BeadID: issue.ID, Agent: assignee, Details: "cleared stale assignee without runtime"})
	}

	allowed := r.spec.AllowedEvents()
	promptPath := dsl.ResolvePromptPath(r.projectRoot, r.spec.Workers.Prompt)
	for _, issue := range queueBeads {
		if activeWorkers >= r.spec.Workers.Count {
			break
		}
		if strings.TrimSpace(issue.Assignee) != "" {
			continue
		}
		attempt, err := r.attempts.Next(issue.ID)
		if err != nil {
			return len(queueBeads), activeWorkers, err
		}
		agentName := process.AgentName(r.runID, issue.ID, attempt)
		claimed, err := r.client.Claim(ctx, issue.ID, agentName)
		if err != nil {
			return len(queueBeads), activeWorkers, err
		}
		if !claimed {
			r.emitter.Emit(Event{Event: "claim_conflict", RunID: r.runID, BeadID: issue.ID, Agent: agentName})
			continue
		}

		token := fmt.Sprintf("%s:%s:%d", r.runID, issue.ID, attempt)
		rt, err := r.manager.Spawn(ctx, process.SpawnSpec{
			RunID:              r.runID,
			Attempt:            attempt,
			BeadID:             issue.ID,
			BeadTitle:          issue.Title,
			BeadDescription:    issue.Description,
			SourceLabel:        r.spec.Source.Label,
			AssignmentToken:    token,
			AllowedTransitions: allowed,
			AgentName:          agentName,
			Provider:           r.spec.Workers.Provider,
			Model:              r.spec.Workers.Model,
			Effort:             r.spec.Workers.Effort,
			PromptPath:         promptPath,
		})
		if err != nil {
			_ = r.client.ClearAssigneeIfMatch(ctx, issue.ID, agentName, r.actor)
			r.emitter.Emit(Event{Event: "spawn_error", RunID: r.runID, BeadID: issue.ID, Agent: agentName, Details: err.Error()})
			continue
		}
		if err := r.registry.Save(rt); err != nil {
			_ = process.Terminate(rt.PID)
			_ = r.client.ClearAssigneeIfMatch(ctx, issue.ID, agentName, r.actor)
			return len(queueBeads), activeWorkers, err
		}
		activeWorkers++
		r.emitter.Emit(Event{
			Event:           "spawn",
			RunID:           r.runID,
			Queue:           r.spec.Name,
			BeadID:          issue.ID,
			AssignmentToken: token,
			Agent:           agentName,
			Provider:        rt.Provider,
			SessionRef:      rt.SessionRef,
			PID:             rt.PID,
		})
	}

	return len(queueBeads), activeWorkers, nil
}

func (r *Runner) processStateComments(ctx context.Context, byBead map[string]process.WorkerRuntime) error {
	if len(byBead) == 0 {
		return nil
	}
	beadIDs := make([]string, 0, len(byBead))
	for beadID := range byBead {
		beadIDs = append(beadIDs, beadID)
	}
	sort.Strings(beadIDs)

	transitions := r.spec.CanonicalTransitions()
	for _, beadID := range beadIDs {
		rt := byBead[beadID]
		comments, err := r.client.ListComments(ctx, beadID)
		if err != nil {
			return err
		}
		cursor := r.cursors.Get(beadID)
		maxSeen := cursor
		transitioned := false

		for _, c := range comments {
			if c.ID <= cursor {
				continue
			}
			if c.ID > maxSeen {
				maxSeen = c.ID
			}
			parsed, ok := agent.ParseStateComment(c.Text)
			if !ok {
				continue
			}
			if parsed.Token != rt.AssignmentToken {
				r.emitter.Emit(Event{
					Event:           "ignored_stale_state",
					RunID:           r.runID,
					BeadID:          beadID,
					CommentID:       c.ID,
					AssignmentToken: parsed.Token,
					Value:           parsed.Event,
					Details:         "token mismatch",
				})
				continue
			}

			target, ok := transitions[parsed.Event]
			if !ok {
				detail := "event not in transitions"
				r.emitter.Emit(Event{Event: "transition_conflict", RunID: r.runID, BeadID: beadID, CommentID: c.ID, AssignmentToken: parsed.Token, Value: parsed.Event, Details: detail})
				_ = r.attention.Upsert(status.AttentionItem{BeadID: beadID, Reason: "transition_conflict", SuggestedAction: "refresh_bead_state_and_repair", Details: detail, At: time.Now().UTC().Format(time.RFC3339)})
				continue
			}

			r.emitter.Emit(Event{Event: "state", RunID: r.runID, BeadID: beadID, AssignmentToken: parsed.Token, Value: parsed.Event, CommentID: c.ID})
			if err := r.client.Transition(ctx, beadID, r.spec.Source.Label, target, rt.AgentName, r.actor); err != nil {
				r.emitter.Emit(Event{Event: "transition_conflict", RunID: r.runID, BeadID: beadID, AssignmentToken: parsed.Token, Value: parsed.Event, Details: err.Error()})
				_ = r.attention.Upsert(status.AttentionItem{BeadID: beadID, Reason: "transition_conflict", SuggestedAction: "refresh_bead_state_and_repair", Details: err.Error(), At: time.Now().UTC().Format(time.RFC3339)})
				continue
			}

			_ = process.Terminate(rt.PID)
			_ = r.registry.Delete(beadID)
			_ = r.cursors.Set(beadID, c.ID)
			_ = r.attention.Clear(beadID, "transition_conflict")
			_ = r.attention.Clear(beadID, "stuck_no_progress")
			_ = r.attention.Clear(beadID, "waiting_input")
			_ = r.attention.Clear(beadID, "orphaned_assignment")

			r.emitter.Emit(Event{Event: "transition", RunID: r.runID, BeadID: beadID, From: r.spec.Source.Label, To: target, AssignmentToken: parsed.Token})
			r.emitter.Emit(Event{Event: "done", RunID: r.runID, BeadID: beadID, AssignmentToken: parsed.Token})
			transitioned = true
			break
		}

		if transitioned {
			continue
		}
		recovered, ok, recErr := recoverStateFromRuntimeLog(rt, transitions)
		if recErr != nil {
			r.emitter.Emit(Event{
				Event:   "state_recovery_error",
				RunID:   r.runID,
				BeadID:  beadID,
				Details: recErr.Error(),
			})
		} else if ok {
			recoveredLine := fmt.Sprintf("STATE %s assignment=%s", recovered.Event, recovered.Token)
			if err := r.client.AddComment(ctx, beadID, recoveredLine); err != nil {
				r.emitter.Emit(Event{
					Event:           "state_recovery_error",
					RunID:           r.runID,
					BeadID:          beadID,
					AssignmentToken: recovered.Token,
					Value:           recovered.Event,
					Details:         err.Error(),
				})
			} else {
				r.emitter.Emit(Event{
					Event:           "state_recovered",
					RunID:           r.runID,
					BeadID:          beadID,
					AssignmentToken: recovered.Token,
					Value:           recovered.Event,
					Details:         "recovered STATE from runtime log and posted comment",
				})
			}
		}
		if maxSeen > cursor {
			if err := r.cursors.Set(beadID, maxSeen); err != nil {
				return err
			}
			rt.LastProcessedCommentID = maxSeen
		}

		// Dead workers that did not produce a transition should not stay
		// assigned forever; clear their claim and remove stale runtime state.
		if !process.IsAlive(rt.PID) {
			_ = r.client.ClearAssigneeIfMatch(ctx, beadID, rt.AgentName, r.actor)
			_ = r.registry.Delete(beadID)
			_ = r.attention.Clear(beadID, "orphaned_assignment")
			_ = r.attention.Clear(beadID, "stuck_no_progress")
			_ = r.attention.Clear(beadID, "waiting_input")
			r.emitter.Emit(Event{
				Event:           "requeue",
				RunID:           r.runID,
				BeadID:          beadID,
				AssignmentToken: rt.AssignmentToken,
				Agent:           rt.AgentName,
				Details:         "removed exited runtime and cleared stale claim",
			})
			continue
		}

		if maxSeen > cursor {
			if err := r.registry.Save(rt); err != nil {
				return err
			}
		}
	}
	return nil
}

func recoverStateFromRuntimeLog(rt process.WorkerRuntime, transitions map[string]string) (agent.ParsedState, bool, error) {
	logPath := strings.TrimSpace(rt.ProcessLogPath)
	if logPath == "" {
		return agent.ParsedState{}, false, nil
	}

	var last agent.ParsedState
	found := false
	_, err := logscan.ForEachLine(logPath, logscan.DefaultMaxLineBytes, func(line string) bool {
		if line == "" {
			return true
		}
		candidates := extractStateCandidatesFromLogLine(line)
		for _, parsed := range candidates {
			if parsed.Token != rt.AssignmentToken {
				continue
			}
			if _, ok := transitions[parsed.Event]; !ok {
				continue
			}
			last = parsed
			found = true
		}
		return true
	})
	if err != nil {
		if os.IsNotExist(err) {
			return agent.ParsedState{}, false, nil
		}
		return agent.ParsedState{}, false, err
	}
	return last, found, nil
}

func extractStateCandidatesFromLogLine(line string) []agent.ParsedState {
	candidates := extractStateCandidatesFromAny(line)
	var raw map[string]any
	if err := json.Unmarshal([]byte(line), &raw); err == nil {
		candidates = append(candidates, extractStateCandidatesFromAny(raw)...)
	}
	return dedupeStateCandidates(candidates)
}

func extractStateCandidatesFromAny(v any) []agent.ParsedState {
	switch t := v.(type) {
	case string:
		return extractStateCandidatesFromText(t)
	case map[string]any:
		out := []agent.ParsedState{}
		for _, key := range []string{"text", "message", "aggregated_output"} {
			if s, ok := t[key].(string); ok {
				out = append(out, extractStateCandidatesFromText(s)...)
			}
		}
		if item, ok := t["item"]; ok {
			out = append(out, extractStateCandidatesFromAny(item)...)
		}
		if items, ok := t["items"]; ok {
			out = append(out, extractStateCandidatesFromAny(items)...)
		}
		return out
	case []any:
		out := []agent.ParsedState{}
		for _, entry := range t {
			out = append(out, extractStateCandidatesFromAny(entry)...)
		}
		return out
	default:
		return nil
	}
}

func extractStateCandidatesFromText(text string) []agent.ParsedState {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	normalized := strings.ReplaceAll(text, "\r\n", "\n")
	lines := strings.Split(normalized, "\n")
	out := make([]agent.ParsedState, 0, len(lines))
	for _, line := range lines {
		parsed, ok := agent.ParseStateComment(line)
		if !ok {
			continue
		}
		out = append(out, parsed)
	}
	return out
}

func dedupeStateCandidates(items []agent.ParsedState) []agent.ParsedState {
	if len(items) <= 1 {
		return items
	}
	seen := map[string]struct{}{}
	out := make([]agent.ParsedState, 0, len(items))
	for _, it := range items {
		key := it.Event + "::" + it.Token
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, it)
	}
	return out
}

func (r *Runner) stopAllWorkers(ctx context.Context) {
	runtimes, err := r.registry.LoadAll()
	if err != nil {
		return
	}
	for _, rt := range runtimes {
		_ = process.Terminate(rt.PID)
		_ = r.client.ClearAssigneeIfMatch(ctx, rt.BeadID, rt.AgentName, r.actor)
		_ = r.registry.Delete(rt.BeadID)
		r.emitter.Emit(Event{Event: "killed", RunID: r.runID, BeadID: rt.BeadID, PID: rt.PID, Reason: "stop_requested"})
	}
}

func (r *Runner) upsertAttention(item status.AttentionItem) bool {
	changed, err := r.attention.UpsertChanged(item)
	if err != nil {
		return false
	}
	return changed
}
