package beads

import (
	"reflect"
	"testing"
)

func TestWithBRGlobalFlagsDefaultEnabled(t *testing.T) {
	t.Setenv("BSW_BR_SQLITE_NATIVE", "")
	c := Client{}
	got := c.withBRGlobalFlags([]string{"list", "--json"})
	want := []string{"--no-auto-import", "--no-auto-flush", "list", "--json"}
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
	if unsupportedGlobalFlags("some other runtime error") {
		t.Fatalf("expected unsupportedGlobalFlags=false for unrelated error")
	}
}
