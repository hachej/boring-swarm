package status

import "testing"

func TestAttentionUpsertChangedDedupesStablePayload(t *testing.T) {
	root := t.TempDir()
	store := NewAttentionStore(root)

	item := AttentionItem{
		BeadID:          "bd-1",
		Reason:          "orphaned_assignment",
		SuggestedAction: "requeue",
		Details:         "missing runtime",
	}
	changed, err := store.UpsertChanged(item)
	if err != nil {
		t.Fatalf("UpsertChanged first call error: %v", err)
	}
	if !changed {
		t.Fatalf("expected first upsert to report changed")
	}

	changed, err = store.UpsertChanged(item)
	if err != nil {
		t.Fatalf("UpsertChanged second call error: %v", err)
	}
	if changed {
		t.Fatalf("expected duplicate upsert payload to be deduped")
	}
}

func TestAttentionClearChangedNoopWhenMissing(t *testing.T) {
	root := t.TempDir()
	store := NewAttentionStore(root)

	changed, err := store.ClearChanged("bd-1", "orphaned_assignment")
	if err != nil {
		t.Fatalf("ClearChanged missing item error: %v", err)
	}
	if changed {
		t.Fatalf("expected clear on missing item to be no-op")
	}
}
