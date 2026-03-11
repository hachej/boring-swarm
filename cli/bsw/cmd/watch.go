package cmd

import (
	"flag"
	"fmt"
	"time"
)

func runWatch(args []string) error {
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	interval := fs.String("interval", "30s", "check interval")
	project := fs.String("project", ".", "project root directory")
	if err := fs.Parse(args); err != nil {
		return err
	}

	dur, err := time.ParseDuration(*interval)
	if err != nil {
		return fmt.Errorf("invalid interval %q: %w", *interval, err)
	}
	if dur <= 0 {
		return fmt.Errorf("interval must be positive, got %s", dur)
	}

	fmt.Printf("Watching workers every %s (Ctrl+C to stop)\n\n", dur)

	projectArgs := []string{"--project", *project}

	for {
		if err := runGC(projectArgs); err != nil {
			fmt.Printf("gc: %v\n", err)
		}
		fmt.Println()
		if err := runStatus(projectArgs); err != nil {
			fmt.Printf("status: %v\n", err)
		}

		time.Sleep(dur)
		fmt.Printf("\n--- %s ---\n", time.Now().Format("15:04:05"))
	}
}
