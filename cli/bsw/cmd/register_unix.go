package cmd

import (
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

func signalHUP() syscall.Signal {
	return syscall.SIGHUP
}

func findBridgePID() (int, error) {
	out, err := exec.Command("pgrep", "-f", "bridge.py").Output()
	if err != nil {
		return 0, err
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 0 {
		return 0, nil
	}
	return strconv.Atoi(strings.TrimSpace(lines[0]))
}
