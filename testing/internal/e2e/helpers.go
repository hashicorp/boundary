package e2e

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"testing"
)

// CommandResult captures the output from running an external command
type CommandResult struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
	Err      error
}

// CliError parses the Stderr from running a boundary command
type CliError struct {
	Status int `json:"status"`
}

const EnvToCheckSkip = "E2E_PASSWORD_AUTH_METHOD_ID"

// RunCommand executes external commands on the system. Returns the results
// of running the provided command.
//
//	RunCommand(context.Background(), "ls")
//	RunCommand(context.Background(), "ls", "-al", "/path")
//
// CommandResult is always valid even if there is an error.
func RunCommand(ctx context.Context, name string, args ...string) *CommandResult {
	var outbuf, errbuf bytes.Buffer

	cmd := exec.CommandContext(ctx, name, args...)
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

// MaybeSkipTest is a check used at the start of the test to determine if the test should run
func MaybeSkipTest(t testing.TB) {
	if _, ok := os.LookupEnv(EnvToCheckSkip); !ok {
		t.Skip(fmt.Sprintf(
			"Skipping test because environment variable '%s' is not set. This is needed for e2e tests.",
			EnvToCheckSkip,
		))
	}
}
