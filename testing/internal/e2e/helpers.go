package e2e

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"testing"
)

// Option is a func that sets optional attributes for a call. This does not need
// to be used directly, but instead option arguments are built from the
// functions in this package. WithX options set a value to that given in the
// argument; DefaultX options indicate that the value should be set to its
// default. When an API call is made options are processed in ther order they
// appear in the function call, so for a given argument X, a succession of WithX
// or DefaultX calls will result in the last call taking effect.
type Option func(*options)

type options struct {
	withArgs []string
	withPipe []string
}

func getOpts(opt ...Option) options {
	opts := options{}
	for _, o := range opt {
		if o != nil {
			o(&opts)
		}
	}

	return opts
}

// CommandResult encapsulates the output from running an external command
type CommandResult struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
	Err      error
}

const EnvToCheckSkip = "E2E_PASSWORD_AUTH_METHOD_ID"

// RunCommand executes external commands on the system. Returns the results
// of running the provided command.
//
//	RunCommand("ls")
//	RunCommand("ls", "-al", "/path")
//
// CommandResult is always valid even if there is an error.
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

// WithArgs is an option to RunCommand that allows the user to specify arguments
// for the provided command
func WithArgs(args ...string) Option {
	return func(o *options) {
		o.withArgs = args
	}
}

// WithPipe is an option to RunCommand that allows the user to specify a command+arguments
// to pipe to
func WithPipe(command ...string) Option {
	return func(o *options) {
		o.withPipe = command
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
