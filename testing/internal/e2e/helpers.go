package e2e

import (
	"bytes"
	"errors"
	"fmt"
	"io"
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
//	RunCommand("ls", WithArgs("-al", "/path"))
//	RunCommand("ls", WithArgs("-al", "/path"), WithPipe("grep", "file"))
//
// CommandResult is always valid even if there is an error.
func RunCommand(command string, opt ...Option) *CommandResult {
	var outbuf, errbuf bytes.Buffer
	var err error
	var c1, c2 *exec.Cmd

	opts := getOpts(opt...)

	if opts.withArgs == nil {
		c1 = exec.Command(command)
	} else {
		c1 = exec.Command(command, opts.withArgs...)
	}

	if opts.withPipe == nil {
		c1.Stdout = &outbuf
		c1.Stderr = &errbuf
		err = c1.Run()
	} else {
		pipeCommand := opts.withPipe[0]
		pipeArgs := opts.withPipe[1:]
		c2 = exec.Command(pipeCommand, pipeArgs...)

		r, w := io.Pipe()
		c1.Stdout = w
		c2.Stdin = r

		c2.Stdout = &outbuf
		c2.Stderr = &errbuf

		c1.Start()
		c2.Start()
		c1.Wait()
		w.Close()
		c2.Wait()
	}

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
