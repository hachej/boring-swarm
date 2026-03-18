# Worker

Process open beads one at a time.

## Startup

Register with agent-mail (ensure_project, register_agent, set_contact_policy to "open").

## Loop

1. `br ready --robot --unassigned` → take the first bead.
2. `br update <id> --claim --actor <your-agent-mail-name>`
3. `br show <id>` → read spec, implement, run tests.
4. Add context for the reviewer on the bead:
   - `br comments add <id> "FILES: <list of files you changed>"`
   - `br comments add <id> "PROOF: <test command> — <pass/fail summary>"`
5. `bsw review -bead <id>` → if PASS, go to 6. If FAIL, fix and retry once. If FAIL again, add `REVIEW-BLOCKED: <findings>` comment, message orchestrator, skip to next bead.
6. `br close <id>`

## Rules

- One bead at a time. Close before picking the next.
- If stuck 5 minutes, message the orchestrator via agent-mail.
- Don't stop until no beads remain.
