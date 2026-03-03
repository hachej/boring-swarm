package logscan

import (
	"strings"
	"testing"
)

func TestForEachLineReaderHandlesLargeLines(t *testing.T) {
	large := strings.Repeat("x", 3*1024*1024)
	input := "first\n" + large + "\nlast\n"
	got := []string{}
	skipped, err := ForEachLineReader(strings.NewReader(input), 4*1024*1024, func(line string) bool {
		got = append(got, line)
		return true
	})
	if err != nil {
		t.Fatalf("ForEachLineReader error: %v", err)
	}
	if skipped != 0 {
		t.Fatalf("expected skipped=0 got=%d", skipped)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 lines got=%d", len(got))
	}
	if got[0] != "first" || got[2] != "last" {
		t.Fatalf("unexpected lines: %#v", got)
	}
}

func TestForEachLineReaderSkipsOverflowLine(t *testing.T) {
	large := strings.Repeat("x", 3*1024*1024)
	input := "ok1\n" + large + "\nok2\n"
	got := []string{}
	skipped, err := ForEachLineReader(strings.NewReader(input), 512*1024, func(line string) bool {
		got = append(got, line)
		return true
	})
	if err != nil {
		t.Fatalf("ForEachLineReader error: %v", err)
	}
	if skipped != 1 {
		t.Fatalf("expected skipped=1 got=%d", skipped)
	}
	if len(got) != 2 || got[0] != "ok1" || got[1] != "ok2" {
		t.Fatalf("unexpected lines: %#v", got)
	}
}
