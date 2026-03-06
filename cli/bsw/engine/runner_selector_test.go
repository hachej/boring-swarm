package engine

import (
	"reflect"
	"testing"

	"boring-swarm/cli/bsw/beads"
)

func TestUnassignedIssues(t *testing.T) {
	items := []beads.Issue{
		{ID: "bd-1", Assignee: ""},
		{ID: "bd-2", Assignee: "agent-a"},
		{ID: "bd-3", Assignee: " "},
	}
	got := unassignedIssues(items)
	want := []beads.Issue{
		{ID: "bd-1", Assignee: ""},
		{ID: "bd-3", Assignee: " "},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unassignedIssues()=%v want %v", got, want)
	}
}

func TestFilterIssuesByIDSet(t *testing.T) {
	items := []beads.Issue{{ID: "bd-1"}, {ID: "bd-2"}, {ID: "bd-3"}}
	got := filterIssuesByIDSet(items, map[string]struct{}{
		"bd-3": {},
		"bd-1": {},
	})
	want := []beads.Issue{{ID: "bd-1"}, {ID: "bd-3"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("filterIssuesByIDSet()=%v want %v", got, want)
	}
}

func TestMoveIssueToFront(t *testing.T) {
	items := []beads.Issue{{ID: "bd-1"}, {ID: "bd-2"}, {ID: "bd-3"}}
	moveIssueToFront(items, "bd-3")
	got := []string{items[0].ID, items[1].ID, items[2].ID}
	want := []string{"bd-3", "bd-2", "bd-1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("moveIssueToFront()=%v want %v", got, want)
	}
}
