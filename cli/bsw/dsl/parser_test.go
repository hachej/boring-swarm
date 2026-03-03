package dsl

import "testing"

func TestParseValidSpec(t *testing.T) {
	src := []byte(`version: 1
name: implementation_workers
source:
  label: needs-impl
workers:
  count: 2
  provider: codex
  model: gpt-5-codex
  effort: high
  prompt: prompts/impl_worker.md
transitions:
  "impl:done": needs-proof
  "impl:error": needs-review
timeout: 4h
`)
	spec, err := ParseBytes(src)
	if err != nil {
		t.Fatalf("ParseBytes failed: %v", err)
	}
	if spec.Version != 1 || spec.Name != "implementation_workers" {
		t.Fatalf("unexpected spec decode: %+v", spec)
	}
	if len(spec.AllowedEvents()) != 2 {
		t.Fatalf("expected 2 allowed events")
	}
}

func TestParseRejectsUnknownField(t *testing.T) {
	src := []byte(`version: 1
name: implementation_workers
source:
  label: needs-impl
workers:
  count: 2
  provider: codex
  model: gpt-5-codex
  prompt: prompts/impl_worker.md
transitions:
  "impl:done": needs-proof
extra_field: nope
`)
	if _, err := ParseBytes(src); err == nil {
		t.Fatalf("expected unknown field error")
	}
}

func TestValidateProvider(t *testing.T) {
	src := []byte(`version: 1
name: implementation_workers
source:
  label: needs-impl
workers:
  count: 2
  provider: not-a-provider
  model: gpt-5-codex
  prompt: prompts/impl_worker.md
transitions:
  "impl:done": needs-proof
`)
	if _, err := ParseBytes(src); err == nil {
		t.Fatalf("expected provider validation error")
	}
}

func TestValidateProviderClaudeCodeAlias(t *testing.T) {
	src := []byte(`version: 1
name: implementation_workers
source:
  label: needs-impl
workers:
  count: 2
  provider: claude-code
  model: claude-sonnet-4-5
  prompt: prompts/impl_worker.md
transitions:
  "impl:done": needs-proof
`)
	if _, err := ParseBytes(src); err != nil {
		t.Fatalf("expected claude-code to pass validation, got: %v", err)
	}
}

func TestValidateProviderCCCAlias(t *testing.T) {
	src := []byte(`version: 1
name: implementation_workers
source:
  label: needs-impl
workers:
  count: 2
  provider: ccc
  model: claude-sonnet-4-5
  prompt: prompts/impl_worker.md
transitions:
  "impl:done": needs-proof
`)
	if _, err := ParseBytes(src); err != nil {
		t.Fatalf("expected ccc alias to pass validation, got: %v", err)
	}
}
