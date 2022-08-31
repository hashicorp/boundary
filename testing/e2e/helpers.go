package e2e

import (
	"bytes"
	"errors"
	"os/exec"
)

type BaseTest struct {
	BoundaryAddress            string `envconfig:"BOUNDARY_ADDR" default:"http://127.0.0.1:9200"`
	BoundaryAuthMethodId       string `envconfig:"BOUNDARY_AUTHMETHOD_ID" default:"ampw_1234567890"`
	BoundaryAdminLoginName     string `envconfig:"BOUNDARY_AUTHENTICATE_PASSWORD_LOGIN_NAME" default:"admin"`
	BoundaryAdminLoginPassword string `envconfig:"BOUNDARY_AUTHENTICATE_PASSWORD_PASSWORD"`
	BoundaryTargetIp           string `envconfig:"BOUNDARY_E2E_TARGET_IP"`
	BoundaryTargetSshKeyPath   string `envconfig:"BOUNDARY_E2E_SSH_KEY_PATH"`
	// !! BoundaryBinPath
	// StateFilePath string `envconfig:"BOUNDARY_STATE_FILEPATH"`
	// VaultAddress
	// VaultToken
	// AwsCredentials
	// AwsAccountId

	// NAME: BoundaryCluster
	// pass boundary client that is already authenticated?

	// !! NEW PACKAGE: Boundary.New User Client ->
	// create a user -> connect to target
}

type CommandResult struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
	Err      error
}

func RunCommand(command []string) CommandResult {
	var outbuf, errbuf bytes.Buffer
	name := command[0]
	args := command[1:]

	cmd := exec.Command(name, args...)
	cmd.Stdout = &outbuf
	cmd.Stderr = &errbuf

	err := cmd.Run()

	var ee *exec.ExitError
	var exitCode int
	if errors.As(err, &ee) {
		exitCode = ee.ExitCode()
	} else {
		exitCode = 0
	}

	return CommandResult{
		Stdout:   outbuf.Bytes(),
		Stderr:   errbuf.Bytes(),
		ExitCode: exitCode,
		Err:      err,
	}
}
