package engine

import (
	"os"
	"testing"
)

func TestAcquireServiceProcessRejectsActive(t *testing.T) {
	root := t.TempDir()
	release, err := acquireServiceProcess(root, "proof_workers", "run-1", os.Getpid())
	if err != nil {
		t.Fatalf("acquire initial service: %v", err)
	}
	defer release()

	_, err = acquireServiceProcess(root, "proof_workers", "run-2", os.Getpid())
	if err == nil {
		t.Fatalf("expected duplicate active service error")
	}
}

func TestAcquireServiceProcessReplacesStale(t *testing.T) {
	root := t.TempDir()
	path := serviceRegistryPath(root, "review_workers")
	if err := os.MkdirAll(serviceRegistryDir(root), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := writeServiceProcess(path, ServiceProcess{
		FlowName: "review_workers",
		PID:      999999,
		RunID:    "stale",
	}); err != nil {
		t.Fatalf("write stale service file: %v", err)
	}

	release, err := acquireServiceProcess(root, "review_workers", "run-3", os.Getpid())
	if err != nil {
		t.Fatalf("acquire should replace stale entry: %v", err)
	}
	defer release()

	items, err := ListServiceProcesses(root)
	if err != nil {
		t.Fatalf("list services: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 service, got %d", len(items))
	}
	if items[0].PID != os.Getpid() {
		t.Fatalf("expected pid=%d got=%d", os.Getpid(), items[0].PID)
	}
}
