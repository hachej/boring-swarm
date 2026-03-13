# boring-swarm

AI agent swarm process manager. Single Go binary at `cli/bsw/`.

## Build & test

```bash
cd cli/bsw && go build -o ~/.local/bin/bsw .
bash eval/scenario_basic.sh   # 65 tests, expects Agent Mail running
```

## Structure

```
cli/bsw/
  cmd/           All commands (spawn, status, kill, stop, gc, logs, etc.)
  process/       Process lifecycle, registry (.bsw/workers/*.json), Agent Mail client
  monitor/       Health checks: PID alive, zombie, tmux pane, stale detection
  persona/       TOML persona loader
  beads/         br CLI wrapper (list beads, clear assignees)
  templates/     Embedded persona templates (worker.toml, reviewer.toml, prompts/)
```

## Key files

- `cmd/root.go` — command router + help text (orchestrator instructions)
- `cmd/spawn.go` — registers with Agent Mail, generates worker ID from agent name
- `process/manager.go` — spawns bg/tmux processes, builds provider commands
- `process/agentmail.go` — Agent Mail JSON-RPC client (register, health check, env vars)
- `process/registry.go` — worker state persistence (.bsw/workers/)
- `monitor/monitor.go` — process health: CheckPID, CheckTmuxPane, CheckWorker

## Conventions

- Workers are identified by their Agent Mail name (e.g. `ScarletRobin`), fallback to `worker-<ts>`
- Registry files: `.bsw/workers/<worker-id>.json`
- Logs: `.bsw/logs/<worker-id>.log`
- Personas: `personas/<name>.toml` + `personas/prompts/<name>.md`
- Provider binary override: `BSW_CODEX_BIN`, `BSW_CLAUDE_BIN` env vars

## External dependencies

- `br` (beads_rust) — work queue CLI
- `codex` or `claude` — AI coding agent
- Agent Mail server at `http://127.0.0.1:8765/mcp/` — token from `AGENT_MAIL_TOKEN` or Vault `secret/agent/mail`
- `tmux` — for interactive mode

## Testing

Mock providers in `eval/mock-codex.sh` and `eval/mock-claude.sh` simulate agent processes. The eval script (`eval/scenario_basic.sh`) tests the full lifecycle without calling real AI APIs.
