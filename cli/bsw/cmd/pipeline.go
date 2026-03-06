package cmd

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"boring-swarm/cli/bsw/beads"
	"boring-swarm/cli/bsw/dsl"
	"boring-swarm/cli/bsw/engine"
)

var pipelines = map[string][]string{
	"plan-review": {
		"flows/plan_refine_queue.yml",
	},
	"plan-split": {
		"flows/plan_decompose_queue.yml",
	},
	"impl": {
		"flows/implement_worker_queue.yml",
	},
	"plan-verify": {
		"flows/plan_verify_queue.yml",
	},
	"full": {
		"flows/plan_refine_queue.yml",
		"flows/plan_decompose_queue.yml",
		"flows/implement_worker_queue.yml",
		"flows/plan_verify_queue.yml",
	},
}

func runPipeline(args []string) error {
	flagArgs, nameArg, extras := splitArgs(args, map[string]bool{
		"project": true,
		"actor":   true,
		"poll":    true,
	})
	fs := flag.NewFlagSet("pipeline", flag.ContinueOnError)
	project := fs.String("project", ".", "project root")
	actor := fs.String("actor", defaultActor, "actor name for br mutations")
	poll := fs.Duration("poll", 2*time.Second, "reconcile interval")
	if err := fs.Parse(flagArgs); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if len(extras) > 0 {
		return fmt.Errorf("unexpected extra arguments: %v", extras)
	}
	if nameArg == "" && fs.NArg() > 0 {
		nameArg = fs.Arg(0)
	}
	if nameArg == "" {
		return fmt.Errorf("pipeline requires a name: %s", pipelineNames())
	}

	flows, ok := pipelines[nameArg]
	if !ok {
		return fmt.Errorf("unknown pipeline %q; available: %s", nameArg, pipelineNames())
	}

	root, err := projectRootFromFlag(*project)
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	return executePipeline(ctx, root, flows, *actor, *poll)
}

func executePipeline(ctx context.Context, root string, flows []string, actor string, poll time.Duration) error {
	client := beads.Client{Workdir: root, Actor: actor}

	for iteration := 1; ; iteration++ {
		if iteration > 1 {
			fmt.Printf("\n--- pipeline iteration %d ---\n", iteration)
		}

		ranAny := false
		for _, flow := range flows {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			flowPath := filepath.Join(root, flow)
			label := flowSourceLabel(flowPath)
			if label == "" {
				fmt.Printf("[pipeline] skipping %s (cannot read source label)\n", flow)
				continue
			}

			count, err := queueDepth(ctx, client, label)
			if err != nil {
				fmt.Printf("[pipeline] warning: cannot check queue %s: %v\n", label, err)
				continue
			}
			if count == 0 {
				fmt.Printf("[pipeline] %s: queue %s empty, skipping\n", flow, label)
				continue
			}

			fmt.Printf("[pipeline] %s: %d beads in %s, running...\n", flow, count, label)
			ranAny = true

			err = engine.Run(ctx, engine.RunOptions{
				ProjectRoot:  root,
				FlowPath:     flowPath,
				Mode:         "oneshot",
				Actor:        actor,
				PollInterval: poll,
			})
			if err != nil {
				if errors.Is(err, context.Canceled) {
					return err
				}
				fmt.Printf("[pipeline] %s finished with error: %v\n", flow, err)
			} else {
				fmt.Printf("[pipeline] %s: done\n", flow)
			}
		}

		if !ranAny {
			fmt.Println("[pipeline] all queues empty, pipeline complete")
			return nil
		}

		// Check if any queue still has work (e.g. plan-verify created new impl beads).
		total := 0
		for _, flow := range flows {
			flowPath := filepath.Join(root, flow)
			label := flowSourceLabel(flowPath)
			if label == "" {
				continue
			}
			n, _ := queueDepth(ctx, client, label)
			if n > 0 {
				fmt.Printf("[pipeline] queue %s has %d beads remaining\n", label, n)
			}
			total += n
		}

		if total == 0 {
			fmt.Println("[pipeline] all queues empty after iteration, pipeline complete")
			return nil
		}
		fmt.Printf("[pipeline] %d beads remaining across queues, looping...\n", total)
	}
}

func queueDepth(ctx context.Context, client beads.Client, label string) (int, error) {
	issues, err := client.ListByLabel(ctx, label)
	if err != nil {
		return 0, err
	}
	return len(issues), nil
}

func flowSourceLabel(flowPath string) string {
	spec, err := dsl.ParseFile(flowPath)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(spec.Source.Label)
}

func pipelineNames() string {
	names := make([]string, 0, len(pipelines))
	for k := range pipelines {
		names = append(names, k)
	}
	return fmt.Sprintf("%v", names)
}
