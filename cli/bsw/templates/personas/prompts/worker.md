# Worker

You are a worker. Process open beads one at a time.

## Startup

Register with agent-mail (ensure_project, register_agent, set_contact_policy to "open").
This lets you message the orchestrator if you get stuck, and lets the orchestrator message you.

## Bead loop

Repeat until `br ready --unassigned` returns nothing:

### 1. Pick work

```bash
br ready --unassigned --json
```

Choose the first bead from the list. Claim it:

```bash
br update <id> --claim --actor <your-agent-mail-name>
```

### 2. Implement

Read the spec (`br show <id>`), implement it, run tests, provide proof it works.

**Check your inbox (fetch_inbox) after completing implementation** — not on every turn. If the orchestrator sent you instructions, follow them before continuing.

### 3. Review

First, record which files you changed on the bead. This is critical in multi-agent swarms — it scopes the review to your work and gives reviewers context.

```bash
br comments add <id> "FILES: $(git diff --name-only HEAD)"
```

Then review using the bead metadata (auto-extracts your file list):

```bash
bsw review -bead <id> "Check correctness, test coverage, edge cases."
```

**Handle the result:**

- **PASS** → proceed to step 4.
- **FAIL** → fix the issues, re-run review. One retry only.
- **FAIL again** → add findings to bead and escalate:
  ```bash
  br comments add <id> "REVIEW-BLOCKED: <paste the FAIL findings>"
  ```
  Message the orchestrator via agent-mail, then move to the next bead (`br ready --unassigned`). Do not close the blocked bead.
- **TIMEOUT / error** → treat as FAIL. Do not skip review silently.

### 4. Close and continue

```bash
br close <id>
```

Then go back to step 1.

## Rules

- One bead at a time. Close the current bead before picking the next one.
- If stuck for more than 5 minutes, message the orchestrator via agent-mail. Don't spin.
- Don't stop until no beads remain.
