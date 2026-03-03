package agent

import (
	"regexp"
	"strings"
)

var (
	stateLineA = regexp.MustCompile(`(?i)^\s*state\s+([a-z][a-z0-9_-]*:[a-z][a-z0-9_-]*)\s+assignment=([^\s]+)\s*$`)
	stateLineB = regexp.MustCompile(`(?i)^\s*state\s*:\s*([a-z][a-z0-9_-]*:[a-z][a-z0-9_-]*)\s+assignment=([^\s]+)\s*$`)
)

type ParsedState struct {
	Event string
	Token string
	Raw   string
}

func ParseStateComment(text string) (ParsedState, bool) {
	line := strings.TrimSpace(text)
	if line == "" {
		return ParsedState{}, false
	}
	if m := stateLineA.FindStringSubmatch(line); len(m) == 3 {
		return ParsedState{Event: strings.ToLower(strings.TrimSpace(m[1])), Token: strings.TrimSpace(m[2]), Raw: line}, true
	}
	if m := stateLineB.FindStringSubmatch(line); len(m) == 3 {
		return ParsedState{Event: strings.ToLower(strings.TrimSpace(m[1])), Token: strings.TrimSpace(m[2]), Raw: line}, true
	}
	return ParsedState{}, false
}
