package cmd

import "boring-swarm/v2/cli/bsw/engine"

func loadRunStateSafe(projectRoot string) (engine.RunState, error) {
	return engine.LoadRunState(projectRoot)
}
