package agent

import "testing"

func TestParseStateCommentVariants(t *testing.T) {
	cases := []struct {
		in    string
		event string
		token string
		ok    bool
	}{
		{"STATE impl:done assignment=run:bd-1:1", "impl:done", "run:bd-1:1", true},
		{"state: proof:failed assignment=run:bd-1:2", "proof:failed", "run:bd-1:2", true},
		{"STATE impl:done", "", "", false},
		{"hello world", "", "", false},
	}
	for _, tc := range cases {
		got, ok := ParseStateComment(tc.in)
		if ok != tc.ok {
			t.Fatalf("ParseStateComment(%q) ok=%v want %v", tc.in, ok, tc.ok)
		}
		if !ok {
			continue
		}
		if got.Event != tc.event || got.Token != tc.token {
			t.Fatalf("ParseStateComment(%q) got=%+v", tc.in, got)
		}
	}
}
