package cmd

import (
	"bufio"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"boring-swarm/cli/bsw/beads"
	"boring-swarm/cli/bsw/dsl"
	"boring-swarm/cli/bsw/process"
	"boring-swarm/cli/bsw/status"
)

//go:embed dashboard.html
var dashboardFS embed.FS

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	project := fs.String("project", ".", "project root")
	addr := fs.String("addr", "127.0.0.1:8787", "bind address")
	flow := fs.String("flow", "", "flow path override")
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

	client := beads.Client{Workdir: root}
	registry := process.NewRegistry(root)

	indexBytes, err := dashboardFS.ReadFile("dashboard.html")
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(indexBytes)
	})

	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		resolved, spec, err := resolveFlowForServe(root, strings.TrimSpace(*flow))
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		snap, err := status.BuildSnapshot(r.Context(), root, client, spec, true)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		snap = augmentSnapshotForDashboard(r.Context(), root, client, snap)
		now := time.Now().UTC()
		_ = appendMetricsSnapshotIfDue(root, snap, now, 30*time.Second)
		flowSummary := map[string]any{}
		if spec != nil {
			flowSummary = map[string]any{
				"name":        spec.Name,
				"source":      spec.Source.Label,
				"transitions": spec.CanonicalTransitions(),
				"workers": map[string]any{
					"count":    spec.Workers.Count,
					"provider": spec.Workers.Provider,
					"model":    spec.Workers.Model,
					"prompt":   spec.Workers.Prompt,
				},
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"project_root":  root,
			"resolved_flow": resolved,
			"snapshot":      snap,
			"flow_summary":  flowSummary,
			"server_time":   now.Format(time.RFC3339),
		})
	})

	mux.HandleFunc("/api/metrics", func(w http.ResponseWriter, r *http.Request) {
		rangeDur := parseDashboardRange(strings.TrimSpace(r.URL.Query().Get("range")))
		resolution := parseDashboardResolution(strings.TrimSpace(r.URL.Query().Get("resolution")))
		now := time.Now().UTC()
		start := now.Add(-rangeDur)

		if _, spec, err := resolveFlowForServe(root, strings.TrimSpace(*flow)); err == nil {
			if snap, err := status.BuildSnapshot(r.Context(), root, client, spec, false); err == nil {
				snap = augmentSnapshotForDashboard(r.Context(), root, client, snap)
				_ = appendMetricsSnapshotIfDue(root, snap, now, 30*time.Second)
			}
		}

		records, err := loadMetricsSnapshots(root, start, now)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		queueSeries, agentSeries := aggregateMetricsSnapshots(records, start, now, resolution)
		eventLog, err := loadRunnerEvents(filepath.Join(root, ".bsw", "logs"), "", now)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		throughput, cycle := buildThroughputAndCycle(eventLog, start, now)
		writeJSON(w, http.StatusOK, map[string]any{
			"generated_at": now.Format(time.RFC3339),
			"range": map[string]any{
				"start":      start.Format(time.RFC3339),
				"end":        now.Format(time.RFC3339),
				"resolution": int(resolution.Seconds()),
			},
			"queues":      queueSeries,
			"agents":      agentSeries,
			"throughput":  throughput,
			"cycle_times": cycle,
		})
	})

	mux.HandleFunc("/api/metrics/transition-timeseries", func(w http.ResponseWriter, r *http.Request) {
		windowHours := 24
		if raw := strings.TrimSpace(r.URL.Query().Get("window_hours")); raw != "" {
			if n, err := strconv.Atoi(raw); err == nil {
				if n < 1 {
					n = 1
				}
				if n > 24*30 {
					n = 24 * 30
				}
				windowHours = n
			}
		}
		bucketSec := 300
		if raw := strings.TrimSpace(r.URL.Query().Get("bucket_seconds")); raw != "" {
			if n, err := strconv.Atoi(raw); err == nil {
				if n < 10 {
					n = 10
				}
				if n > 24*3600 {
					n = 24 * 3600
				}
				bucketSec = n
			}
		}

		now := time.Now().UTC()
		windowStart := now.Add(-time.Duration(windowHours) * time.Hour)
		bucket := time.Duration(bucketSec) * time.Second
		points, statuses, totals, err := buildTransitionTimeseries(filepath.Join(root, ".bsw", "logs"), windowStart, now, bucket)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"generated_at":     now.Format(time.RFC3339),
			"window_start":     windowStart.Format(time.RFC3339),
			"window_end":       now.Format(time.RFC3339),
			"bucket_seconds":   bucketSec,
			"statuses":         statuses,
			"points":           points,
			"totals":           totals,
			"closed_total":     totals["closed"],
			"transition_total": sumMapInt(totals),
		})
	})

	mux.HandleFunc("/api/bead/", func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/api/bead/"))
		historyOnly := false
		if strings.HasSuffix(rest, "/history") {
			historyOnly = true
			rest = strings.TrimSpace(strings.TrimSuffix(rest, "/history"))
		}
		beadID := rest
		if beadID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing bead id"})
			return
		}
		issue, err := client.GetIssue(r.Context(), beadID)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": err.Error()})
			return
		}
		comments, _ := client.ListComments(r.Context(), beadID)
		runtime, _ := registry.Load(beadID)
		history := buildBeadHistory(root, issue, comments, runtime)
		if historyOnly {
			writeJSON(w, http.StatusOK, map[string]any{
				"bead_id": beadID,
				"history": history,
			})
			return
		}
		input, output := buildBeadInputOutput(issue, comments, runtime)
		writeJSON(w, http.StatusOK, map[string]any{
			"issue":    issue,
			"comments": comments,
			"runtime":  runtime,
			"input":    input,
			"output":   output,
			"history":  history,
		})
	})

	mux.HandleFunc("/api/agent/", func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/api/agent/"))
		if rest == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing bead id"})
			return
		}
		if strings.HasSuffix(rest, "/logs") {
			beadID := strings.TrimSpace(strings.TrimSuffix(rest, "/logs"))
			if beadID == "" {
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing bead id"})
				return
			}
			runtime, err := registry.Load(beadID)
			if err != nil {
				writeJSON(w, http.StatusNotFound, map[string]any{"error": err.Error()})
				return
			}
			tail := 120
			if raw := strings.TrimSpace(r.URL.Query().Get("tail")); raw != "" {
				if n, err := strconv.Atoi(raw); err == nil {
					if n < 1 {
						n = 1
					}
					if n > 1000 {
						n = 1000
					}
					tail = n
				}
			}
			lines, err := readTailLines(runtime.ProcessLogPath, tail, 512*1024)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
				return
			}
			entries := parseLogEntries(lines)
			sort.SliceStable(entries, func(i, j int) bool {
				ti := parseLooseTime(entries[i].Timestamp)
				tj := parseLooseTime(entries[j].Timestamp)
				if ti.IsZero() && tj.IsZero() {
					return entries[i].Order > entries[j].Order
				}
				if ti.IsZero() {
					return false
				}
				if tj.IsZero() {
					return true
				}
				if ti.Equal(tj) {
					return entries[i].Order > entries[j].Order
				}
				return ti.After(tj)
			})
			events := normalizeLogEvents(entries)
			writeJSON(w, http.StatusOK, map[string]any{
				"bead_id":    beadID,
				"log_path":   runtime.ProcessLogPath,
				"tail_lines": tail,
				"lines":      lines,
				"entries":    entries,
				"events":     events,
			})
			return
		}

		beadID := rest
		runtime, err := registry.Load(beadID)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": err.Error()})
			return
		}
		issue, _ := client.GetIssue(context.Background(), beadID)
		writeJSON(w, http.StatusOK, map[string]any{
			"runtime": runtime,
			"issue":   issue,
		})
	})

	agentMailBase := strings.TrimSpace(os.Getenv("AGENT_MAIL_URL"))
	if agentMailBase == "" {
		agentMailBase = "http://127.0.0.1:8765"
	}

	mux.HandleFunc("/api/agentmail", func(w http.ResponseWriter, r *http.Request) {
		limit := "200"
		if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
			limit = raw
		}
		bodies := "true"
		if raw := strings.TrimSpace(r.URL.Query().Get("include_bodies")); raw != "" {
			bodies = raw
		}
		url := agentMailBase + "/mail/api/unified-inbox?limit=" + limit + "&include_bodies=" + bodies + "&include_projects=true"
		resp, err := http.Get(url)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{"error": "agent-mail unreachable: " + err.Error()})
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(body)
	})

	mux.HandleFunc("/api/agentmail/send", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "POST required"})
			return
		}
		var req struct {
			Project    string   `json:"project"`
			Recipients []string `json:"recipients"`
			Subject    string   `json:"subject"`
			BodyMD     string   `json:"body_md"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON: " + err.Error()})
			return
		}
		if strings.TrimSpace(req.Project) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "project is required"})
			return
		}
		payload, _ := json.Marshal(map[string]any{
			"recipients": req.Recipients,
			"subject":    req.Subject,
			"body_md":    req.BodyMD,
		})
		url := agentMailBase + "/mail/" + strings.TrimSpace(req.Project) + "/overseer/send"
		resp, err := http.Post(url, "application/json", strings.NewReader(string(payload)))
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{"error": "agent-mail unreachable: " + err.Error()})
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(body)
	})

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})

	fmt.Printf("bsw dashboard listening on http://%s\n", strings.TrimSpace(*addr))
	srv := &http.Server{
		Addr:              strings.TrimSpace(*addr),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	return srv.ListenAndServe()
}

func resolveFlowForServe(projectRoot, override string) (string, *dsl.FlowSpec, error) {
	candidates := []string{}
	if strings.TrimSpace(override) != "" {
		candidates = append(candidates, strings.TrimSpace(override))
	}
	if rs, err := loadRunStateSafe(projectRoot); err == nil && strings.TrimSpace(rs.Flow) != "" {
		candidates = append(candidates, strings.TrimSpace(rs.Flow))
	}
	candidates = append(candidates,
		filepath.Join(projectRoot, "flows", "implement_worker_queue.yml"),
	)

	seen := map[string]struct{}{}
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if !filepath.IsAbs(c) {
			c = filepath.Join(projectRoot, c)
		}
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}
		spec, err := dsl.ParseFile(c)
		if err != nil {
			continue
		}
		return c, spec, nil
	}
	return "", nil, fmt.Errorf("no valid flow found (set --flow or run bsw init)")
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func readTailLines(path string, maxLines int, maxBytes int64) ([]string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return []string{}, nil
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := st.Size()
	start := int64(0)
	if size > maxBytes {
		start = size - maxBytes
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return nil, err
	}
	buf, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	text := string(buf)
	if start > 0 {
		if idx := strings.IndexByte(text, '\n'); idx >= 0 && idx+1 < len(text) {
			text = text[idx+1:]
		}
	}
	rawLines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	lines := make([]string, 0, len(rawLines))
	for _, line := range rawLines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		lines = append(lines, line)
	}
	if maxLines <= 0 || len(lines) <= maxLines {
		return lines, nil
	}
	return lines[len(lines)-maxLines:], nil
}

type transitionPoint struct {
	TS     string         `json:"ts"`
	Counts map[string]int `json:"counts"`
	Total  int            `json:"total"`
}

type transitionEvent struct {
	Event string `json:"event"`
	TS    string `json:"ts"`
	To    string `json:"to"`
}

func buildTransitionTimeseries(logDir string, windowStart, windowEnd time.Time, bucket time.Duration) ([]transitionPoint, []string, map[string]int, error) {
	entries, err := os.ReadDir(logDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []transitionPoint{}, []string{}, map[string]int{}, nil
		}
		return nil, nil, nil, err
	}

	buckets := map[time.Time]map[string]int{}
	statusSet := map[string]struct{}{}
	totals := map[string]int{}

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		path := filepath.Join(logDir, e.Name())
		st, err := e.Info()
		if err == nil && st.ModTime().UTC().Before(windowStart.Add(-bucket)) {
			continue
		}
		if err := scanTransitionLog(path, windowStart, windowEnd, bucket, buckets, statusSet, totals); err != nil {
			return nil, nil, nil, err
		}
	}

	statuses := make([]string, 0, len(statusSet))
	for s := range statusSet {
		statuses = append(statuses, s)
	}
	sort.Strings(statuses)

	keys := make([]time.Time, 0, len(buckets))
	for t := range buckets {
		keys = append(keys, t)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].Before(keys[j]) })

	points := make([]transitionPoint, 0, len(keys))
	for _, t := range keys {
		counts := buckets[t]
		total := 0
		for _, v := range counts {
			total += v
		}
		points = append(points, transitionPoint{
			TS:     t.UTC().Format(time.RFC3339),
			Counts: counts,
			Total:  total,
		})
	}

	return points, statuses, totals, nil
}

func scanTransitionLog(path string, windowStart, windowEnd time.Time, bucket time.Duration, buckets map[time.Time]map[string]int, statusSet map[string]struct{}, totals map[string]int) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 2*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var ev transitionEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue
		}
		if strings.TrimSpace(ev.Event) != "transition" {
			continue
		}
		status := strings.TrimSpace(ev.To)
		if status == "" {
			continue
		}
		ts, err := time.Parse(time.RFC3339, strings.TrimSpace(ev.TS))
		if err != nil {
			continue
		}
		ts = ts.UTC()
		if ts.Before(windowStart) || ts.After(windowEnd) {
			continue
		}
		b := ts.Truncate(bucket)
		m := buckets[b]
		if m == nil {
			m = map[string]int{}
			buckets[b] = m
		}
		m[status]++
		statusSet[status] = struct{}{}
		totals[status]++
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return nil
}

func sumMapInt(m map[string]int) int {
	total := 0
	for _, v := range m {
		total += v
	}
	return total
}

type logEntry struct {
	Order     int    `json:"order"`
	Timestamp string `json:"timestamp,omitempty"`
	Type      string `json:"type,omitempty"`
	Summary   string `json:"summary"`
	Raw       string `json:"raw"`
}

var inlineTSPattern = regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z`)

func parseLogEntries(lines []string) []logEntry {
	out := make([]logEntry, 0, len(lines))
	for i, line := range lines {
		entry := logEntry{
			Order:   i + 1,
			Summary: strings.TrimSpace(line),
			Raw:     line,
		}
		var raw map[string]any
		if err := json.Unmarshal([]byte(line), &raw); err == nil {
			entry.Timestamp = firstTimeString(raw, "ts", "timestamp", "created_at", "time")
			entry.Type = strings.TrimSpace(asStringAny(raw["type"]))
			if msg := asStringAny(raw["message"]); msg != "" {
				entry.Summary = msg
			} else if val := asStringAny(raw["event"]); val != "" {
				entry.Summary = val
			}
		} else if m := inlineTSPattern.FindString(line); m != "" {
			entry.Timestamp = m
		}
		if strings.TrimSpace(entry.Summary) == "" {
			entry.Summary = line
		}
		out = append(out, entry)
	}
	return out
}

func firstTimeString(raw map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := raw[k]; ok {
			s := strings.TrimSpace(asStringAny(v))
			if s != "" {
				return s
			}
		}
	}
	return ""
}

func asStringAny(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case int64:
		return strconv.FormatInt(t, 10)
	default:
		return ""
	}
}

func parseLooseTime(v string) time.Time {
	s := strings.TrimSpace(v)
	if s == "" {
		return time.Time{}
	}
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05",
	}
	for _, l := range layouts {
		if t, err := time.Parse(l, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

func augmentSnapshotForDashboard(ctx context.Context, projectRoot string, client beads.Client, snap status.Snapshot) status.Snapshot {
	labels := dashboardQueueLabels(projectRoot, snap)
	if len(labels) == 0 {
		return snap
	}

	byID := make(map[string]status.BeadView, len(snap.Beads))
	for _, b := range snap.Beads {
		byID[b.BeadID] = b
	}

	queues := make(map[string]status.QueueStats, len(snap.Queues)+len(labels))
	for k, v := range snap.Queues {
		queues[k] = v
	}

	for _, label := range labels {
		issues, err := client.ListByLabel(ctx, label)
		if err != nil {
			continue
		}
		q := status.QueueStats{Total: len(issues)}
		for _, issue := range issues {
			if strings.TrimSpace(issue.Assignee) == "" {
				q.Unassigned++
			} else {
				q.Assigned++
			}
			existing, ok := byID[issue.ID]
			if !ok {
				byID[issue.ID] = status.BeadView{
					BeadID:   issue.ID,
					Title:    strings.TrimSpace(issue.Title),
					Label:    label,
					Assignee: strings.TrimSpace(issue.Assignee),
				}
				continue
			}
			// Keep richer runtime fields from existing entry; refresh core issue fields.
			if strings.TrimSpace(existing.Title) == "" {
				existing.Title = strings.TrimSpace(issue.Title)
			}
			if strings.TrimSpace(existing.Assignee) == "" {
				existing.Assignee = strings.TrimSpace(issue.Assignee)
			}
			if strings.TrimSpace(existing.Label) == "" {
				existing.Label = label
			}
			byID[issue.ID] = existing
		}
		queues[label] = q
	}

	beadsOut := make([]status.BeadView, 0, len(byID))
	for _, b := range byID {
		beadsOut = append(beadsOut, b)
	}
	sort.Slice(beadsOut, func(i, j int) bool { return beadsOut[i].BeadID < beadsOut[j].BeadID })

	snap.Queues = queues
	snap.Beads = beadsOut
	return snap
}

func dashboardQueueLabels(projectRoot string, snap status.Snapshot) []string {
	labels := map[string]struct{}{
		"needs-impl": {},
		"closed":     {},
	}
	for label := range snap.Queues {
		if strings.TrimSpace(label) == "" {
			continue
		}
		labels[label] = struct{}{}
	}

	flowsDir := filepath.Join(projectRoot, "flows")
	entries, err := os.ReadDir(flowsDir)
	if err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := strings.ToLower(strings.TrimSpace(entry.Name()))
			if !(strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml")) {
				continue
			}
			spec, err := dsl.ParseFile(filepath.Join(flowsDir, entry.Name()))
			if err != nil || spec == nil {
				continue
			}
			src := strings.TrimSpace(spec.Source.Label)
			if src != "" {
				labels[src] = struct{}{}
			}
			for _, target := range spec.Transitions {
				t := strings.TrimSpace(target)
				if t != "" {
					labels[t] = struct{}{}
				}
			}
		}
	}

	out := make([]string, 0, len(labels))
	for label := range labels {
		out = append(out, label)
	}
	sort.Strings(out)
	return out
}
