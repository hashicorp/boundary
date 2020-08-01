package cli

import (
	"os/exec"
)

const cmdPath = "/tmp/watchtower"

func Run(args ...string) ([]byte, error) {
	return exec.Command(cmdPath, args...).Output()
}

func Start(args ...string) (*exec.Cmd, error) {
	cmd := exec.Command(cmdPath, args...)
	err := cmd.Start()
	if err != nil {
		return cmd, err
	}

	return cmd, nil
}
