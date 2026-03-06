package beads

import (
	"reflect"
	"testing"
)

func TestWithBRGlobalFlagsDefaultEnabled(t *testing.T) {
	t.Setenv("BSW_BR_SQLITE_NATIVE", "")
	c := Client{}
	got := c.withBRGlobalFlags([]string{"list", "--json"})
	want := []string{"--no-auto-flush", "list", "--json"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("withBRGlobalFlags()=%v want %v", got, want)
	}
}

func TestWithBRGlobalFlagsDisabled(t *testing.T) {
	t.Setenv("BSW_BR_SQLITE_NATIVE", "false")
	c := Client{}
	got := c.withBRGlobalFlags([]string{"list", "--json"})
	want := []string{"list", "--json"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("withBRGlobalFlags()=%v want %v", got, want)
	}
}

func TestUnsupportedGlobalFlags(t *testing.T) {
	if !unsupportedGlobalFlags("error: unexpected argument '--no-auto-import' found") {
		t.Fatalf("expected unsupportedGlobalFlags=true for unexpected argument message")
	}
	if !unsupportedGlobalFlags("error: unexpected argument '--no-auto-flush' found") {
		t.Fatalf("expected unsupportedGlobalFlags=true for no-auto-flush message")
	}
	if unsupportedGlobalFlags("some other runtime error") {
		t.Fatalf("expected unsupportedGlobalFlags=false for unrelated error")
	}
}

func TestAutoImportDisabledDesync(t *testing.T) {
	msg := "CONFIG_ERROR: JSONL is newer than the database (auto-import disabled)"
	if !autoImportDisabledDesync(msg) {
		t.Fatalf("expected autoImportDisabledDesync=true")
	}
	if autoImportDisabledDesync("some other error") {
		t.Fatalf("expected autoImportDisabledDesync=false")
	}
}

func TestIssueIDsFromPayloadArray(t *testing.T) {
	raw := []byte(`[{"id":"bd-1"},{"id":"bd-2"},{"id":"bd-1"}]`)
	got := issueIDsFromPayload(raw)
	want := []string{"bd-1", "bd-2"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("issueIDsFromPayload()=%v want %v", got, want)
	}
}

func TestIssueIDsFromPayloadNestedObject(t *testing.T) {
	raw := []byte(`{"next":{"issue":{"id":"bd-9"}}}`)
	got := issueIDsFromPayload(raw)
	want := []string{"bd-9"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("issueIDsFromPayload()=%v want %v", got, want)
	}
}

func TestIssueIDsFromPayloadTextFallback(t *testing.T) {
	raw := []byte("top pick: bd-55")
	got := issueIDsFromPayload(raw)
	want := []string{"bd-55"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("issueIDsFromPayload()=%v want %v", got, want)
	}
}

func TestReadyArgsIncludeUnlimitedAndLabel(t *testing.T) {
	got := readyArgs("needs-impl", true)
	want := []string{"ready", "--json", "--limit", "0", "--label", "needs-impl", "--unassigned"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("readyArgs()=%v want %v", got, want)
	}
}

func TestReadyArgsDefault(t *testing.T) {
	got := readyArgs("", false)
	want := []string{"ready", "--json", "--limit", "0"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("readyArgs()=%v want %v", got, want)
	}
}
