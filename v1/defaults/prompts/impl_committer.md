# Committer Worker

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
