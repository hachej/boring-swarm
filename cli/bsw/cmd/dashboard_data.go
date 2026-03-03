package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"boring-swarm/cli/bsw/agent"
	"boring-swarm/cli/bsw/beads"
	"boring-swarm/cli/bsw/process"
	"boring-swarm/cli/bsw/status"
)

const (
	defaultMetricsRange      = 4 * time.Hour
	defaultMetricsResolution = 5 * time.Minute
)

type metricsSnapshotRecord struct {
	TS         string                       `json:"ts"`
	Queues     map[string]status.QueueStats `json:"queues"`
	AgentState map[string]int               `json:"agent_state"`
	Agents     int                          `json:"agents"`
	Beads      int                          `json:"beads"`
	Attention  int                          `json:"attention"`
}

type metricsQueuePoint struct {
	TS         string `json:"ts"`
	Total      int    `json:"total"`
	Assigned   int    `json:"assigned"`
	Unassigned int    `json:"unassigned"`
}

type metricsAgentPoint struct {
	TS           string `json:"ts"`
	Active       int    `json:"active"`
	WaitingInput int    `json:"waiting_input"`
	Idle         int    `json:"idle"`
	Blocked      int    `json:"blocked"`
	Exited       int    `json:"exited"`
	Unknown      int    `json:"unknown"`
	Total        int    `json:"total"`
}

type metricsThroughputPoint struct {
	Hour      string `json:"hour"`
	Completed int    `json:"completed"`
	Failed    int    `json:"failed"`
}

type metricsCyclePoint struct {
	Hour       string  `json:"hour"`
	AvgMinutes float64 `json:"avg_minutes"`
	P95Minutes float64 `json:"p95_minutes"`
}

type runnerEvent struct {
	Event           string `json:"event"`
	RunID           string `json:"run_id,omitempty"`
	Queue           string `json:"queue,omitempty"`
	BeadID          string `json:"bead_id,omitempty"`
	AssignmentToken string `json:"assignment_token,omitempty"`
	Agent           string `json:"agent,omitempty"`
	Provider        string `json:"provider,omitempty"`
	SessionRef      string `json:"session_ref,omitempty"`
	PID             int    `json:"pid,omitempty"`
	Value           string `json:"value,omitempty"`
	From            string `json:"from,omitempty"`
	To              string `json:"to,omitempty"`
	CommentID       int64  `json:"comment_id,omitempty"`
	Reason          string `json:"reason,omitempty"`
	SuggestedAction string `json:"suggested_action,omitempty"`
	Details         string `json:"details,omitempty"`
	TS              string `json:"ts"`
}

type beadHistoryEvent struct {
	TS              string `json:"ts"`
	Kind            string `json:"kind"`
	Label           string `json:"label,omitempty"`
	From            string `json:"from,omitempty"`
	To              string `json:"to,omitempty"`
	StateEvent      string `json:"state_event,omitempty"`
	AssignmentToken string `json:"assignment_token,omitempty"`
	Agent           string `json:"agent,omitempty"`
	Detail          string `json:"detail,omitempty"`
}

type beadHistorySegment struct {
	Label           string `json:"label"`
	Start           string `json:"start"`
	End             string `json:"end"`
	DurationSeconds int64  `json:"duration_seconds"`
	Agent           string `json:"agent,omitempty"`
	Active          bool   `json:"active"`
}

type beadHistory struct {
	Events   []beadHistoryEvent   `json:"events"`
	Segments []beadHistorySegment `json:"segments"`
	Summary  map[string]any       `json:"summary"`
}

type normalizedLogEvent struct {
	Order     int            `json:"order"`
	Timestamp string         `json:"timestamp,omitempty"`
	Kind      string         `json:"kind"`
	Label     string         `json:"label"`
	Severity  string         `json:"severity"`
	Summary   string         `json:"summary"`
	Raw       string         `json:"raw"`
	RawJSON   map[string]any `json:"raw_json,omitempty"`
}

type eventAt struct {
	At    time.Time
	Event runnerEvent
}

func parseDashboardRange(raw string) time.Duration {
	return parseDashboardDuration(raw, defaultMetricsRange, 30*time.Minute, 7*24*time.Hour)
}

func parseDashboardResolution(raw string) time.Duration {
	return parseDashboardDuration(raw, defaultMetricsResolution, 30*time.Second, time.Hour)
}

func parseDashboardDuration(raw string, fallback, min, max time.Duration) time.Duration {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" {
		return fallback
	}
	if strings.HasSuffix(s, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err == nil && n > 0 {
			d := time.Duration(n) * 24 * time.Hour
			if d < min {
				return min
			}
			if d > max {
				return max
			}
			return d
		}
		return fallback
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return fallback
	}
	if d < min {
		return min
	}
	if d > max {
		return max
	}
	return d
}

func metricsSnapshotFile(projectRoot string) string {
	return filepath.Join(projectRoot, ".bsw", "metrics", "snapshots.jsonl")
}

func appendMetricsSnapshotIfDue(projectRoot string, snap status.Snapshot, now time.Time, minInterval time.Duration) error {
	path := metricsSnapshotFile(projectRoot)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	lastAt := lastMetricsSnapshotTime(path)
	if !lastAt.IsZero() && now.Sub(lastAt) < minInterval {
		return nil
	}

	record := metricsSnapshotRecord{
		TS:         now.UTC().Format(time.RFC3339),
		Queues:     cloneQueueStats(snap.Queues),
		AgentState: countAgentStates(snap.Agents),
		Agents:     len(snap.Agents),
		Beads:      len(snap.Beads),
		Attention:  len(snap.Attention),
	}
	line, err := json.Marshal(record)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(line, '\n'))
	return err
}

func cloneQueueStats(in map[string]status.QueueStats) map[string]status.QueueStats {
	out := make(map[string]status.QueueStats, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func countAgentStates(agents []status.AgentView) map[string]int {
	out := map[string]int{
		"active":        0,
		"waiting_input": 0,
		"idle":          0,
		"blocked":       0,
		"exited":        0,
		"unknown":       0,
	}
	for _, a := range agents {
		st := strings.TrimSpace(a.ActivityState)
		if st == "" {
			st = "unknown"
		}
		if _, ok := out[st]; !ok {
			out["unknown"]++
			continue
		}
		out[st]++
	}
	return out
}

func lastMetricsSnapshotTime(path string) time.Time {
	lines, err := readTailLines(path, 1, 128*1024)
	if err != nil || len(lines) == 0 {
		return time.Time{}
	}
	var rec metricsSnapshotRecord
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		return time.Time{}
	}
	return parseLooseTime(rec.TS)
}

func loadMetricsSnapshots(projectRoot string, start, end time.Time) ([]metricsSnapshotRecord, error) {
	path := metricsSnapshotFile(projectRoot)
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []metricsSnapshotRecord{}, nil
		}
		return nil, err
	}
	defer f.Close()

	out := []metricsSnapshotRecord{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 2*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var rec metricsSnapshotRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		at := parseLooseTime(rec.TS)
		if at.IsZero() {
			continue
		}
		if at.Before(start) || at.After(end) {
			continue
		}
		out = append(out, rec)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		return parseLooseTime(out[i].TS).Before(parseLooseTime(out[j].TS))
	})
	return out, nil
}

func aggregateMetricsSnapshots(records []metricsSnapshotRecord, start, end time.Time, resolution time.Duration) (map[string][]metricsQueuePoint, []metricsAgentPoint) {
	queueOut := map[string][]metricsQueuePoint{}
	agentOut := []metricsAgentPoint{}
	if len(records) == 0 {
		return queueOut, agentOut
	}

	type recAt struct {
		At  time.Time
		Rec metricsSnapshotRecord
	}
	items := make([]recAt, 0, len(records))
	labelSet := map[string]struct{}{}
	for _, rec := range records {
		at := parseLooseTime(rec.TS)
		if at.IsZero() {
			continue
		}
		items = append(items, recAt{At: at, Rec: rec})
		for label := range rec.Queues {
			labelSet[label] = struct{}{}
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].At.Before(items[j].At) })
	if len(items) == 0 {
		return queueOut, agentOut
	}
	labels := make([]string, 0, len(labelSet))
	for label := range labelSet {
		labels = append(labels, label)
	}
	sort.Strings(labels)
	for _, label := range labels {
		queueOut[label] = []metricsQueuePoint{}
	}

	i := 0
	var current *metricsSnapshotRecord
	bucket := start.UTC().Truncate(resolution)
	for !bucket.After(end) {
		for i < len(items) && !items[i].At.After(bucket) {
			rec := items[i].Rec
			current = &rec
			i++
		}
		if current != nil {
			ts := bucket.Format(time.RFC3339)
			for _, label := range labels {
				q := current.Queues[label]
				queueOut[label] = append(queueOut[label], metricsQueuePoint{
					TS:         ts,
					Total:      q.Total,
					Assigned:   q.Assigned,
					Unassigned: q.Unassigned,
				})
			}
			agent := metricsAgentPoint{
				TS:           ts,
				Active:       current.AgentState["active"],
				WaitingInput: current.AgentState["waiting_input"],
				Idle:         current.AgentState["idle"],
				Blocked:      current.AgentState["blocked"],
				Exited:       current.AgentState["exited"],
				Unknown:      current.AgentState["unknown"],
				Total:        current.Agents,
			}
			agentOut = append(agentOut, agent)
		}
		bucket = bucket.Add(resolution)
	}
	return queueOut, agentOut
}

func loadRunnerEvents(logDir, beadFilter string, end time.Time) ([]eventAt, error) {
	entries, err := os.ReadDir(logDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []eventAt{}, nil
		}
		return nil, err
	}
	needle := ""
	if strings.TrimSpace(beadFilter) != "" {
		needle = fmt.Sprintf("\"bead_id\":\"%s\"", strings.TrimSpace(beadFilter))
	}
	out := []eventAt{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".jsonl") {
			continue
		}
		path := filepath.Join(logDir, entry.Name())
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			if needle != "" && !strings.Contains(line, needle) {
				continue
			}
			var ev runnerEvent
			if err := json.Unmarshal([]byte(line), &ev); err != nil {
				continue
			}
			if strings.TrimSpace(ev.Event) == "" {
				continue
			}
			at := parseLooseTime(ev.TS)
			if at.IsZero() {
				continue
			}
			if !end.IsZero() && at.After(end) {
				continue
			}
			out = append(out, eventAt{At: at, Event: ev})
		}
		_ = f.Close()
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].At.Equal(out[j].At) {
			return out[i].Event.Event < out[j].Event.Event
		}
		return out[i].At.Before(out[j].At)
	})
	return out, nil
}

func buildThroughputAndCycle(events []eventAt, start, end time.Time) ([]metricsThroughputPoint, []metricsCyclePoint) {
	spawnByToken := map[string]time.Time{}
	type row struct {
		Completed int
		Failed    int
		Durations []float64
	}
	perHour := map[time.Time]*row{}

	for _, item := range events {
		ev := item.Event
		if strings.TrimSpace(ev.Event) == "spawn" && strings.TrimSpace(ev.AssignmentToken) != "" {
			if _, ok := spawnByToken[ev.AssignmentToken]; !ok {
				spawnByToken[ev.AssignmentToken] = item.At
			}
		}
		if item.At.Before(start) || item.At.After(end) {
			continue
		}

		hour := item.At.UTC().Truncate(time.Hour)
		r := perHour[hour]
		if r == nil {
			r = &row{}
			perHour[hour] = r
		}

		switch strings.TrimSpace(ev.Event) {
		case "transition":
			if isCompletionTarget(ev.To) {
				r.Completed++
			}
			if isFailureTarget(ev.To) {
				r.Failed++
			}
			if strings.TrimSpace(ev.AssignmentToken) != "" {
				if spawnAt, ok := spawnByToken[ev.AssignmentToken]; ok && !spawnAt.After(item.At) {
					mins := item.At.Sub(spawnAt).Minutes()
					if mins >= 0 && mins <= 14*24*60 {
						r.Durations = append(r.Durations, mins)
					}
				}
			}
		case "state":
			if isFailureState(ev.Value) {
				r.Failed++
			}
		}
	}

	throughput := []metricsThroughputPoint{}
	cycle := []metricsCyclePoint{}
	hour := start.UTC().Truncate(time.Hour)
	endHour := end.UTC().Truncate(time.Hour)
	for !hour.After(endHour) {
		r := perHour[hour]
		point := metricsThroughputPoint{Hour: hour.Format(time.RFC3339)}
		cyclePoint := metricsCyclePoint{Hour: hour.Format(time.RFC3339)}
		if r != nil {
			point.Completed = r.Completed
			point.Failed = r.Failed
			if len(r.Durations) > 0 {
				avg := 0.0
				for _, d := range r.Durations {
					avg += d
				}
				avg = avg / float64(len(r.Durations))
				cyclePoint.AvgMinutes = round2(avg)
				cyclePoint.P95Minutes = round2(percentile(r.Durations, 95))
			}
		}
		throughput = append(throughput, point)
		cycle = append(cycle, cyclePoint)
		hour = hour.Add(time.Hour)
	}
	return throughput, cycle
}

func isCompletionTarget(label string) bool {
	l := strings.ToLower(strings.TrimSpace(label))
	if l == "" {
		return false
	}
	return strings.Contains(l, "done") || strings.Contains(l, "review") || strings.Contains(l, "closed")
}

func isFailureTarget(label string) bool {
	l := strings.ToLower(strings.TrimSpace(label))
	if l == "" {
		return false
	}
	return strings.Contains(l, "error") || strings.Contains(l, "failed")
}

func isFailureState(v string) bool {
	s := strings.ToLower(strings.TrimSpace(v))
	return strings.HasSuffix(s, ":failed") || strings.HasSuffix(s, ":error")
}

func percentile(values []float64, p float64) float64 {
	if len(values) == 0 {
		return 0
	}
	items := append([]float64(nil), values...)
	sort.Float64s(items)
	if len(items) == 1 {
		return items[0]
	}
	if p <= 0 {
		return items[0]
	}
	if p >= 100 {
		return items[len(items)-1]
	}
	pos := (p / 100) * float64(len(items)-1)
	lower := int(pos)
	upper := lower + 1
	if upper >= len(items) {
		return items[lower]
	}
	weight := pos - float64(lower)
	return items[lower]*(1-weight) + items[upper]*weight
}

func round2(v float64) float64 {
	return math.Round(v*100) / 100
}

func buildBeadHistory(projectRoot string, issue beads.Issue, comments []beads.Comment, rt process.WorkerRuntime) beadHistory {
	now := time.Now().UTC()
	evs, _ := loadRunnerEvents(filepath.Join(projectRoot, ".bsw", "logs"), issue.ID, time.Time{})
	historyEvents := make([]beadHistoryEvent, 0, len(evs)+len(comments))
	agentByToken := map[string]string{}
	transitions := []eventAt{}
	for _, item := range evs {
		ev := item.Event
		if strings.TrimSpace(ev.Event) == "spawn" && strings.TrimSpace(ev.AssignmentToken) != "" && strings.TrimSpace(ev.Agent) != "" {
			agentByToken[ev.AssignmentToken] = ev.Agent
		}
		if strings.TrimSpace(ev.Event) == "transition" {
			transitions = append(transitions, item)
		}
		h := beadHistoryEvent{
			TS:              item.At.Format(time.RFC3339),
			Kind:            ev.Event,
			From:            strings.TrimSpace(ev.From),
			To:              strings.TrimSpace(ev.To),
			StateEvent:      strings.TrimSpace(ev.Value),
			AssignmentToken: strings.TrimSpace(ev.AssignmentToken),
			Agent:           strings.TrimSpace(ev.Agent),
			Detail:          strings.TrimSpace(ev.Details),
		}
		if h.To != "" {
			h.Label = h.To
		} else if h.From != "" {
			h.Label = h.From
		}
		if h.Detail == "" {
			switch h.Kind {
			case "spawn":
				h.Detail = "worker spawned"
			case "state":
				h.Detail = h.StateEvent
			case "transition":
				h.Detail = strings.TrimSpace(h.From) + " -> " + strings.TrimSpace(h.To)
			case "killed":
				h.Detail = strings.TrimSpace(ev.Reason)
			}
		}
		historyEvents = append(historyEvents, h)
	}
	for _, c := range comments {
		parsed, ok := agent.ParseStateComment(c.Text)
		if !ok {
			continue
		}
		historyEvents = append(historyEvents, beadHistoryEvent{
			TS:              strings.TrimSpace(c.CreatedAt),
			Kind:            "state_comment",
			StateEvent:      parsed.Event,
			AssignmentToken: parsed.Token,
			Agent:           strings.TrimSpace(c.Author),
			Detail:          parsed.Raw,
		})
	}
	sort.Slice(historyEvents, func(i, j int) bool {
		ti := parseLooseTime(historyEvents[i].TS)
		tj := parseLooseTime(historyEvents[j].TS)
		if ti.Equal(tj) {
			return historyEvents[i].Kind < historyEvents[j].Kind
		}
		return ti.Before(tj)
	})

	segments := make([]beadHistorySegment, 0, len(transitions)+1)
	sort.Slice(transitions, func(i, j int) bool {
		return transitions[i].At.Before(transitions[j].At)
	})
	segmentStart := parseLooseTime(rt.StartedAt)
	if segmentStart.IsZero() && len(transitions) > 0 {
		segmentStart = transitions[0].At
	}
	currentLabel := inferIssueLabel(issue.Labels, rt.SourceLabel)
	if len(transitions) > 0 && strings.TrimSpace(transitions[0].Event.From) != "" {
		currentLabel = strings.TrimSpace(transitions[0].Event.From)
	}
	for _, tr := range transitions {
		to := strings.TrimSpace(tr.Event.To)
		if segmentStart.IsZero() {
			segmentStart = tr.At
		}
		if currentLabel == "" {
			currentLabel = strings.TrimSpace(tr.Event.From)
		}
		if !segmentStart.IsZero() && tr.At.After(segmentStart) && currentLabel != "" {
			segments = append(segments, beadHistorySegment{
				Label:           currentLabel,
				Start:           segmentStart.Format(time.RFC3339),
				End:             tr.At.Format(time.RFC3339),
				DurationSeconds: int64(tr.At.Sub(segmentStart).Seconds()),
				Agent:           agentByToken[strings.TrimSpace(tr.Event.AssignmentToken)],
				Active:          false,
			})
		}
		currentLabel = to
		segmentStart = tr.At
	}
	finalEnd := parseLooseTime(issue.UpdatedAt)
	if finalEnd.IsZero() {
		finalEnd = parseLooseTime(rt.LastProgressTS)
	}
	if finalEnd.IsZero() {
		finalEnd = now
	}
	if currentLabel != "" && !segmentStart.IsZero() && finalEnd.After(segmentStart) {
		segments = append(segments, beadHistorySegment{
			Label:           currentLabel,
			Start:           segmentStart.Format(time.RFC3339),
			End:             finalEnd.Format(time.RFC3339),
			DurationSeconds: int64(finalEnd.Sub(segmentStart).Seconds()),
			Agent:           strings.TrimSpace(rt.AgentName),
			Active:          true,
		})
	}
	if len(segments) == 0 {
		start := parseLooseTime(rt.StartedAt)
		end := parseLooseTime(rt.LastProgressTS)
		if start.IsZero() {
			start = now
		}
		if end.IsZero() || end.Before(start) {
			end = now
		}
		segments = append(segments, beadHistorySegment{
			Label:           inferIssueLabel(issue.Labels, rt.SourceLabel),
			Start:           start.Format(time.RFC3339),
			End:             end.Format(time.RFC3339),
			DurationSeconds: int64(end.Sub(start).Seconds()),
			Agent:           strings.TrimSpace(rt.AgentName),
			Active:          strings.TrimSpace(rt.ActivityState) == "active",
		})
	}

	total := int64(0)
	longest := int64(0)
	bottleneck := ""
	agentSet := map[string]struct{}{}
	for _, s := range segments {
		total += s.DurationSeconds
		if s.DurationSeconds > longest {
			longest = s.DurationSeconds
			bottleneck = s.Label
		}
		if strings.TrimSpace(s.Agent) != "" {
			agentSet[s.Agent] = struct{}{}
		}
	}

	return beadHistory{
		Events:   historyEvents,
		Segments: segments,
		Summary: map[string]any{
			"total_cycle_seconds": total,
			"transition_count":    len(transitions),
			"bottleneck_label":    bottleneck,
			"agent_changes":       len(agentSet),
		},
	}
}

func inferIssueLabel(labels []string, fallback string) string {
	for _, l := range labels {
		lt := strings.TrimSpace(l)
		if strings.HasPrefix(lt, "needs-") || strings.Contains(lt, "done") || strings.Contains(lt, "review") {
			return lt
		}
	}
	return strings.TrimSpace(fallback)
}

func buildBeadInputOutput(issue beads.Issue, comments []beads.Comment, rt process.WorkerRuntime) (map[string]any, map[string]any) {
	input := map[string]any{
		"id":          issue.ID,
		"title":       issue.Title,
		"description": issue.Description,
	}
	if strings.TrimSpace(rt.RuntimePayloadPath) != "" {
		if payload, ok := readJSONFile(rt.RuntimePayloadPath); ok {
			input["runtime_payload"] = payload
		}
	}
	if strings.TrimSpace(rt.PromptPath) != "" {
		input["prompt_path"] = rt.PromptPath
		input["prompt_excerpt"] = readTextExcerpt(rt.PromptPath, 2200)
	}

	output := map[string]any{}
	for i := len(comments) - 1; i >= 0; i-- {
		c := comments[i]
		if parsed, ok := agent.ParseStateComment(c.Text); ok {
			output["state_event"] = parsed.Event
			output["state_assignment_token"] = parsed.Token
			output["state_timestamp"] = c.CreatedAt
			output["state_author"] = c.Author
			output["state_comment"] = c.Text
			break
		}
	}
	for i := len(comments) - 1; i >= 0; i-- {
		c := comments[i]
		if strings.TrimSpace(c.Text) != "" {
			output["latest_comment"] = c.Text
			output["latest_comment_author"] = c.Author
			output["latest_comment_timestamp"] = c.CreatedAt
			break
		}
	}
	if msg := extractLatestAgentMessage(rt.ProcessLogPath); msg != "" {
		output["agent_summary"] = msg
	}
	return input, output
}

func readJSONFile(path string) (map[string]any, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, false
	}
	return out, true
}

func readTextExcerpt(path string, max int) string {
	if max <= 0 {
		max = 2000
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	s := strings.TrimSpace(string(b))
	if len(s) <= max {
		return s
	}
	return s[:max] + "\n..."
}

func extractLatestAgentMessage(logPath string) string {
	lines, err := readTailLines(logPath, 320, 2*1024*1024)
	if err != nil {
		return ""
	}
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		var raw map[string]any
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			continue
		}
		if item, ok := raw["item"].(map[string]any); ok {
			t := strings.ToLower(strings.TrimSpace(asStringAny(item["type"])))
			if t == "agent_message" {
				if msg := strings.TrimSpace(asStringAny(item["text"])); msg != "" {
					return trimLen(msg, 5000)
				}
			}
		}
		t := strings.ToLower(strings.TrimSpace(asStringAny(raw["type"])))
		switch t {
		case "assistant":
			if msg := strings.TrimSpace(asStringAny(raw["message"])); msg != "" {
				return trimLen(msg, 5000)
			}
		case "result":
			if msg := strings.TrimSpace(asStringAny(raw["message"])); msg != "" {
				return trimLen(msg, 5000)
			}
		}
	}
	return ""
}

func trimLen(s string, n int) string {
	if n <= 0 {
		return s
	}
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func normalizeLogEvents(entries []logEntry) []normalizedLogEvent {
	out := make([]normalizedLogEvent, 0, len(entries))
	for _, entry := range entries {
		ev := normalizedLogEvent{
			Order:     entry.Order,
			Timestamp: entry.Timestamp,
			Kind:      "other",
			Label:     "EVENT",
			Severity:  "info",
			Summary:   strings.TrimSpace(entry.Summary),
			Raw:       entry.Raw,
		}
		var raw map[string]any
		if err := json.Unmarshal([]byte(entry.Raw), &raw); err == nil {
			ev.RawJSON = raw
			applyLogSemantics(&ev, raw)
		}
		if strings.TrimSpace(ev.Timestamp) == "" {
			ev.Timestamp = inferLogTimestamp(ev.RawJSON, entry.Raw)
		}
		if strings.TrimSpace(ev.Summary) == "" {
			ev.Summary = "(no summary)"
		}
		out = append(out, ev)
	}
	return out
}

func applyLogSemantics(ev *normalizedLogEvent, raw map[string]any) {
	t := strings.ToLower(strings.TrimSpace(asStringAny(raw["type"])))
	sub := strings.ToLower(strings.TrimSpace(asStringAny(raw["subtype"])))
	if item, ok := raw["item"].(map[string]any); ok {
		itemType := strings.ToLower(strings.TrimSpace(asStringAny(item["type"])))
		switch itemType {
		case "agent_message":
			ev.Kind = "message"
			ev.Label = "ASSISTANT"
			if txt := strings.TrimSpace(asStringAny(item["text"])); txt != "" {
				ev.Summary = trimLen(txt, 160)
			}
		case "command_execution":
			ev.Kind = "tool"
			ev.Label = "TOOL_USE"
			if cmd := strings.TrimSpace(asStringAny(item["command"])); cmd != "" {
				ev.Summary = trimLen(cmd, 160)
			}
		case "reasoning":
			ev.Kind = "message"
			ev.Label = "REASONING"
			if txt := strings.TrimSpace(asStringAny(item["text"])); txt != "" {
				ev.Summary = trimLen(txt, 160)
			}
		}
		if ts := strings.TrimSpace(asStringAny(item["timestamp"])); ts != "" && strings.TrimSpace(ev.Timestamp) == "" {
			ev.Timestamp = ts
		}
	}

	switch {
	case t == "system" && sub == "init":
		ev.Kind = "init"
		ev.Label = "SESSION_INIT"
		if sid := strings.TrimSpace(asStringAny(raw["session_id"])); sid != "" {
			ev.Summary = "session_id: " + sid
		}
	case t == "system" && strings.Contains(sub, "permission"):
		ev.Kind = "permission"
		ev.Label = "PERMISSION_REQUEST"
		ev.Severity = "warn"
		if msg := strings.TrimSpace(asStringAny(raw["message"])); msg != "" {
			ev.Summary = trimLen(msg, 160)
		}
	case t == "assistant":
		ev.Kind = "message"
		ev.Label = "ASSISTANT"
		if msg := strings.TrimSpace(asStringAny(raw["message"])); msg != "" {
			ev.Summary = trimLen(msg, 160)
		}
	case t == "tool_use":
		ev.Kind = "tool"
		ev.Label = "TOOL_USE"
		tool := strings.TrimSpace(asStringAny(raw["tool"]))
		msg := strings.TrimSpace(asStringAny(raw["message"]))
		if tool != "" && msg != "" {
			ev.Summary = trimLen(tool+": "+msg, 160)
		} else if tool != "" {
			ev.Summary = trimLen(tool, 160)
		}
	case t == "result":
		if asBoolAny(raw["is_error"]) || strings.Contains(sub, "error") {
			ev.Kind = "error"
			ev.Label = "ERROR"
			ev.Severity = "error"
		} else {
			ev.Kind = "success"
			ev.Label = "RESULT"
			ev.Severity = "success"
		}
		if msg := strings.TrimSpace(asStringAny(raw["message"])); msg != "" {
			ev.Summary = trimLen(msg, 160)
		}
	case t == "thread.started":
		ev.Kind = "init"
		ev.Label = "THREAD_STARTED"
		if tid := strings.TrimSpace(asStringAny(raw["thread_id"])); tid != "" {
			ev.Summary = "thread_id: " + tid
		}
	case t == "turn.started":
		ev.Kind = "turn"
		ev.Label = "TURN_STARTED"
	case t == "turn.completed":
		ev.Kind = "success"
		ev.Label = "TURN_COMPLETED"
		ev.Severity = "success"
	}

	if strings.Contains(t, "approval") || strings.Contains(strings.ToLower(ev.Summary), "approval") {
		ev.Kind = "permission"
		ev.Label = "APPROVAL_REQUIRED"
		ev.Severity = "warn"
	}
	if strings.Contains(t, "error") {
		ev.Kind = "error"
		ev.Label = "ERROR"
		ev.Severity = "error"
	}
}

func inferLogTimestamp(raw map[string]any, line string) string {
	if raw != nil {
		if v := firstTimeString(raw, "ts", "timestamp", "created_at", "time"); strings.TrimSpace(v) != "" {
			return v
		}
		if item, ok := raw["item"].(map[string]any); ok {
			if v := firstTimeString(item, "ts", "timestamp", "created_at", "time"); strings.TrimSpace(v) != "" {
				return v
			}
		}
	}
	if m := inlineTSPattern.FindString(line); m != "" {
		return m
	}
	return ""
}

func asBoolAny(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return strings.EqualFold(strings.TrimSpace(t), "true")
	default:
		return false
	}
}
