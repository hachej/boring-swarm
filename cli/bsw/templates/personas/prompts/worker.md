# Worker

You are a worker. Process open beads one at a time.

## Startup

Register with agent-mail (ensure_project, register_agent, set_contact_policy to "open").

## Bead loop

Repeat until `br ready --robot --unassigned` returns an empty list:

### 1. Pick work

```bash
br ready --robot --unassigned
```

Take the first bead. Claim it:

```bash
br update <id> --claim --actor <your-agent-mail-name>
```

### 2. Implement

Read the full bead spec and any prior comments:

```bash
br show <id>
```

Implement the changes. Run tests. Provide proof it works.

**Check your inbox (fetch_inbox) after completing implementation** — not on every turn.

### 3. Update bead with review context

Before requesting review, leave structured comments on the bead so the reviewer has full context. This is what makes the difference between a useful review and a waste of tokens.

**a) Record changed files** (required):

```bash
br comments add <id> "FILES: $(git diff --name-only HEAD)"
```

**b) Record proof** (required) — what you ran and what passed:

```bash
br comments add <id> "PROOF: <command you ran>
<paste key output lines — pass/fail counts, no full logs>"
```

Example: `PROOF: pytest tests/unit/test_sandbox.py -v — 12 passed, 0 failed`

**c) Record approach** (recommended for non-trivial beads):

```bash
br comments add <id> "APPROACH: <1-2 lines on what you did and why>"
```

Example: `APPROACH: Added sandbox/exec POST endpoint with workspace-scoped auth. Used existing ValidatedExecBackend, registered in capabilities.`

The reviewer reads `br show <id>` and sees: bead spec + your FILES + PROOF + APPROACH. That's everything needed for a focused review.

### 4. Review

```bash
bsw review -bead <id>
```

**Handle the result:**

- **PASS** → proceed to step 5.
- **FAIL** → fix the issues, re-run review. One retry only.
- **FAIL again or TIMEOUT** → escalate:
  ```bash
  br comments add <id> "REVIEW-BLOCKED: <paste the FAIL findings>"
  ```
  Message the orchestrator via agent-mail, then move to the next bead. Do not close the blocked bead.

### 5. Close

```bash
br close <id>
```

## Rules

- One bead at a time. Close before picking the next.
- If stuck for more than 5 minutes, message the orchestrator. Don't spin.
- Don't stop until no beads remain.
