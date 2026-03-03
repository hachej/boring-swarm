package status

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"boring-swarm/cli/bsw/beads"
	"boring-swarm/cli/bsw/dsl"
	"boring-swarm/cli/bsw/process"
)

type QueueStats struct {
	Total      int `json:"total"`
	Unassigned int `json:"unassigned"`
	Assigned   int `json:"assigned"`
}

type BeadView struct {
	BeadID          string `json:"bead_id"`
	Title           string `json:"title,omitempty"`
	Label           string `json:"label"`
	Assignee        string `json:"assignee,omitempty"`
	AssignmentToken string `json:"assignment_token,omitempty"`
	ActivityState   string `json:"activity_state,omitempty"`
	LastStateEvent  string `json:"last_state_event,omitempty"`
	LastProgressTS  string `json:"last_progress_ts,omitempty"`
	Reason          string `json:"reason,omitempty"`
}

type AgentView struct {
	AgentName     string `json:"agent_name"`
	BeadID        string `json:"bead_id"`
	SourceLabel   string `json:"source_label,omitempty"`
	Provider      string `json:"provider"`
	SessionRef    string `json:"session_ref,omitempty"`
	ResumeCommand string `json:"resume_command,omitempty"`
	PID           int    `json:"pid"`
	ActivityState string `json:"activity_state"`
	Reason        string `json:"reason,omitempty"`
}

type Snapshot struct {
	Run       RunState              `json:"run"`
	Queues    map[string]QueueStats `json:"queues"`
	Beads     []BeadView            `json:"beads"`
	Agents    []AgentView           `json:"agents"`
	Attention []AttentionItem       `json:"attention"`
}

type RunState struct {
	RunID     string `json:"run_id"`
	Flow      string `json:"flow"`
	FlowName  string `json:"flow_name,omitempty"`
	Mode      string `json:"mode"`
	StartedAt string `json:"started_at"`
	PID       int    `json:"pid,omitempty"`
	Status    string `json:"status"`
}

func BuildSnapshot(ctx context.Context, projectRoot string, client beads.Client, spec *dsl.FlowSpec, explain bool) (Snapshot, error) {
	run, _ := loadRunState(projectRoot)
	reg := process.NewRegistry(projectRoot)
	runtimes, err := reg.LoadAll()
	if err != nil {
		return Snapshot{}, err
	}

	timeout := 4 * time.Hour
	if spec != nil {
		if d, err := spec.TimeoutDuration(); err == nil {
			timeout = d
		}
	}

	labels := collectLabels(spec)
	queues := map[string]QueueStats{}
	beadByID := map[string]BeadView{}
	for _, label := range labels {
		issues, err := client.ListByLabel(ctx, label)
		if err != nil {
			continue
		}
		q := QueueStats{Total: len(issues)}
		for _, issue := range issues {
			if strings.TrimSpace(issue.Assignee) == "" {
				q.Unassigned++
			} else {
				q.Assigned++
			}
			if _, ok := beadByID[issue.ID]; !ok {
				beadByID[issue.ID] = BeadView{
					BeadID:   issue.ID,
					Title:    strings.TrimSpace(issue.Title),
					Label:    label,
					Assignee: strings.TrimSpace(issue.Assignee),
				}
			}
		}
		queues[label] = q
	}

	rtByBead := map[string]process.WorkerRuntime{}
	agents := make([]AgentView, 0, len(runtimes))
	for _, rt := range runtimes {
		rtByBead[rt.BeadID] = rt
		reason := ""
		if !process.IsAlive(rt.PID) {
			reason = "process_not_running"
		}
		agents = append(agents, AgentView{
			AgentName:     rt.AgentName,
			BeadID:        rt.BeadID,
			SourceLabel:   rt.SourceLabel,
			Provider:      rt.Provider,
			SessionRef:    rt.SessionRef,
			ResumeCommand: rt.ResumeCommand,
			PID:           rt.PID,
			ActivityState: rt.ActivityState,
			Reason:        maybeExplain(explain, reason),
		})
	}
	sort.Slice(agents, func(i, j int) bool { return agents[i].BeadID < agents[j].BeadID })

	beadsOut := make([]BeadView, 0, len(beadByID))
	for _, v := range beadByID {
		rt, ok := rtByBead[v.BeadID]
		if ok {
			v.AssignmentToken = rt.AssignmentToken
			v.ActivityState = rt.ActivityState
			v.LastStateEvent = rt.LastStateEvent
			v.LastProgressTS = rt.LastProgressTS
			if explain && !process.IsAlive(rt.PID) {
				v.Reason = "registry_entry_present_but_pid_not_alive"
			}
		} else if strings.TrimSpace(v.Assignee) != "" {
			v.ActivityState = "unknown"
			if explain {
				v.Reason = "assigned_bead_without_registry_entry"
			}
		}
		beadsOut = append(beadsOut, v)
	}
	sort.Slice(beadsOut, func(i, j int) bool { return beadsOut[i].BeadID < beadsOut[j].BeadID })

	attention := computeAttention(beadsOut, runtimes, timeout, explain)
	store := NewAttentionStore(projectRoot)
	stored, _ := store.Load()
	attention = mergeAttention(attention, stored)

	return Snapshot{
		Run:       run,
		Queues:    queues,
		Beads:     beadsOut,
		Agents:    agents,
		Attention: attention,
	}, nil
}

func loadRunState(projectRoot string) (RunState, error) {
	path := filepath.Join(projectRoot, ".bsw", "run.json")
	b, err := os.ReadFile(path)
	if err != nil {
		return RunState{}, err
	}
	var rs RunState
	if err := json.Unmarshal(b, &rs); err != nil {
		return RunState{}, err
	}
	return rs, nil
}

func maybeExplain(explain bool, value string) string {
	if !explain {
		return ""
	}
	return value
}

func collectLabels(spec *dsl.FlowSpec) []string {
	if spec == nil {
		return nil
	}
	seen := map[string]struct{}{}
	out := []string{}
	if strings.TrimSpace(spec.Source.Label) != "" {
		seen[spec.Source.Label] = struct{}{}
		out = append(out, spec.Source.Label)
	}
	for _, target := range spec.Transitions {
		t := strings.TrimSpace(target)
		if t == "" {
			continue
		}
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

func computeAttention(beadsOut []BeadView, runtimes []process.WorkerRuntime, timeout time.Duration, explain bool) []AttentionItem {
	now := time.Now().UTC()
	items := []AttentionItem{}
	for _, bead := range beadsOut {
		if strings.TrimSpace(bead.Assignee) != "" && strings.TrimSpace(bead.AssignmentToken) == "" {
			items = append(items, AttentionItem{
				BeadID:          bead.BeadID,
				Reason:          "orphaned_assignment",
				SuggestedAction: "reconcile_and_clear_stale_claim",
				Details:         maybeExplain(explain, "bead is assigned but no active runtime registry entry"),
				At:              now.Format(time.RFC3339),
			})
		}
	}
	for _, rt := range runtimes {
		if rt.ActivityState == "waiting_input" {
			items = append(items, AttentionItem{
				BeadID:          rt.BeadID,
				Reason:          "waiting_input",
				SuggestedAction: "send_mail_then_ping",
				Details:         maybeExplain(explain, "provider requested user input/approval"),
				At:              now.Format(time.RFC3339),
			})
			continue
		}
		if rt.ActivityState == "exited" {
			items = append(items, AttentionItem{
				BeadID:          rt.BeadID,
				Reason:          "orphaned_assignment",
				SuggestedAction: "inspect_and_requeue",
				Details:         maybeExplain(explain, "worker process exited while bead may still be assigned"),
				At:              now.Format(time.RFC3339),
			})
			continue
		}
		if !process.IsAlive(rt.PID) {
			continue
		}
		last := process.ParseTS(rt.LastProgressTS)
		if last.IsZero() {
			last = process.ParseTS(rt.StartedAt)
		}
		if !last.IsZero() && now.Sub(last) > timeout {
			items = append(items, AttentionItem{
				BeadID:          rt.BeadID,
				Reason:          "stuck_no_progress",
				SuggestedAction: "inspect_resume_command_or_kill",
				Details:         maybeExplain(explain, "runtime exceeded timeout without progress and is not waiting_input"),
				At:              now.Format(time.RFC3339),
			})
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].BeadID == items[j].BeadID {
			return items[i].Reason < items[j].Reason
		}
		return items[i].BeadID < items[j].BeadID
	})
	return dedupeAttention(items)
}

func mergeAttention(a, b []AttentionItem) []AttentionItem {
	all := append([]AttentionItem{}, a...)
	for _, it := range b {
		// Keep persistent operator-facing signals from the store, but let
		// fast-changing runtime health signals be derived from live state.
		switch strings.TrimSpace(it.Reason) {
		case "orphaned_assignment", "waiting_input", "stuck_no_progress":
			continue
		}
		all = append(all, it)
	}
	return dedupeAttention(all)
}

func dedupeAttention(items []AttentionItem) []AttentionItem {
	seen := map[string]AttentionItem{}
	for _, it := range items {
		k := it.BeadID + "::" + it.Reason
		seen[k] = it
	}
	out := make([]AttentionItem, 0, len(seen))
	for _, it := range seen {
		out = append(out, it)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].BeadID == out[j].BeadID {
			return out[i].Reason < out[j].Reason
		}
		return out[i].BeadID < out[j].BeadID
	})
	return out
}
