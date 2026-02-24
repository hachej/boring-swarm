# boring-swarm

Self-contained multi-agent swarm orchestration. One binary (bsw), default prompts, and workflow definitions.

## Install

```bash
uv tool install boring-swarm
```

Or with pip/pipx:

```bash
pipx install boring-swarm
```

## Structure

```
boring-swarm/
├── cli/bsw/              # Go source — compiled into platform wheels via go-to-wheel
├── defaults/
│   ├── prompts/
│   │   ├── roles/        # implementer.md, proofer.md, reviewer.md
│   │   └── workflows/    # swarm_init.md, bead_lifecycle.md
│   └── flow.yaml         # Default state machine definition
├── docs/
└── deps.toml             # External dependency declarations
```

## Dependencies

External — installed separately:

| Dep | Role |
|-----|------|
| **br** | Work item CRUD (beads) |
| **bv** | Verification / robot ops |
| **ntm** | Tmux session + pane management |
| **agent-mail** | Inter-agent messaging (MCP) |

## Prompt resolution

bsw looks for prompts in this order:
1. `.bsw/prompts/` (project-local override)
2. `boring-swarm/defaults/prompts/` (shipped defaults)

Same for `flow.yaml`.

## Build wheels locally

Requires Go 1.24+ and [go-to-wheel](https://github.com/simonw/go-to-wheel):

```bash
pip install go-to-wheel
go-to-wheel cli/bsw --name boring-swarm --version 0.1.0 --entry-point bsw
```

Wheels are built automatically on GitHub release via CI.
