package cmd

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"boring-swarm/v2/cli/bsw/agent"
	"boring-swarm/v2/cli/bsw/dsl"
	"boring-swarm/v2/cli/bsw/process"
)

func runDoctor(args []string) error {
	flagArgs, flowArg, extras := splitArgs(args, map[string]bool{
		"project": true,
	})
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	project := fs.String("project", ".", "project root")
	if err := fs.Parse(flagArgs); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if len(extras) > 0 {
		return fmt.Errorf("unexpected extra arguments: %v", extras)
	}
	root, err := projectRootFromFlag(*project)
	if err != nil {
		return err
	}

	flowPath := flowArg
	if flowPath == "" && fs.NArg() > 0 {
		flowPath = fs.Arg(0)
	}
	if flowPath == "" {
		rs, err := loadRunStateSafe(root)
		if err == nil {
			flowPath = rs.Flow
		}
	}
	if flowPath == "" {
		flowPath = filepath.Join(root, "flows", "implement_worker_queue.yml")
	}
	if !filepath.IsAbs(flowPath) {
		flowPath = filepath.Join(root, flowPath)
	}

	problems := 0
	if _, err := exec.LookPath("br"); err != nil {
		fmt.Println("[fail] br not found in PATH")
		problems++
	} else {
		fmt.Println("[ok] br found")
	}

	spec, err := dsl.ParseFile(flowPath)
	if err != nil {
		fmt.Printf("[fail] flow parse: %v\n", err)
		problems++
	} else {
		fmt.Printf("[ok] flow parse: %s\n", flowPath)
		promptPath := dsl.ResolvePromptPath(root, spec.Workers.Prompt)
		if _, err := os.Stat(promptPath); err != nil {
			fmt.Printf("[fail] workers.prompt missing: %s\n", promptPath)
			problems++
		} else {
			fmt.Printf("[ok] workers.prompt exists: %s\n", promptPath)
		}
		provider := agent.NormalizeProvider(spec.Workers.Provider)
		providerBin := process.ResolveProviderBinary(provider)
		if _, err := exec.LookPath(providerBin); err != nil {
			fmt.Printf("[fail] provider binary missing: %s (workers.provider=%s)\n", providerBin, spec.Workers.Provider)
			problems++
		} else {
			fmt.Printf("[ok] provider binary found: %s (workers.provider=%s)\n", providerBin, spec.Workers.Provider)
		}
	}

	if err := checkBRWorkspace(root); err != nil {
		fmt.Printf("[fail] beads workspace: %v\n", err)
		problems++
	} else {
		fmt.Println("[ok] beads workspace available")
	}

	if problems > 0 {
		return fmt.Errorf("doctor found %d problem(s)", problems)
	}
	fmt.Println("doctor: all checks passed")
	return nil
}

func checkBRWorkspace(root string) error {
	cmd := exec.Command("br", "where")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("br where failed: %s", string(out))
	}
	return nil
}
