package e2e

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"testing"
)

// CommandResult encapsulates the output from running an external command
type CommandResult struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
	Err      error
}

const EnvToCheckSkip = "E2E_PASSWORD_AUTH_METHOD_ID"

// RunCommand executes external commands on the system. Returns the results
// of running the provided command. CommandResult is always valid even if there is
// an error.
func RunCommand(name string, args ...string) *CommandResult {
	var outbuf, errbuf bytes.Buffer

	cmd := exec.Command(name, args...)
	cmd.Stdout = &outbuf
	cmd.Stderr = &errbuf

	err := cmd.Run()

	var ee *exec.ExitError
	var exitCode int
	if errors.As(err, &ee) {
		exitCode = ee.ExitCode()
	}

	return &CommandResult{
		Stdout:   outbuf.Bytes(),
		Stderr:   errbuf.Bytes(),
		ExitCode: exitCode,
		Err:      err,
	}
}

func MaybeSkipTest(t *testing.T) {
	if _, ok := os.LookupEnv(EnvToCheckSkip); !ok {
		t.Skip(fmt.Sprintf(
			"Skipping test because environment variable '%s' is not set. This is needed for e2e tests.",
			EnvToCheckSkip,
		))
	}
}
