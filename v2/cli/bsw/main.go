package main

import (
	"fmt"
	"os"

	"boring-swarm/v2/cli/bsw/cmd"
)

func main() {
	if err := cmd.Execute(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
