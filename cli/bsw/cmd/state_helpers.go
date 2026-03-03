package cmd

import "boring-swarm/cli/bsw/engine"

func loadRunStateSafe(projectRoot string) (engine.RunState, error) {
	return engine.LoadRunState(projectRoot)
}
