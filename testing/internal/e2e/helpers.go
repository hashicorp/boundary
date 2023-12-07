// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


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
	withEnv  map[string]string
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

const EnvToCheckSkip = "E2E_TESTS"

// RunCommand executes external commands on the system. Returns the results
// of running the provided command.
//
//	RunCommand(context.Background(), "ls")
//	RunCommand(context.Background(), "ls", WithArgs("-al", "/path"))
//
// CommandResult is always valid even if there is an error.
func RunCommand(ctx context.Context, command string, opt ...Option) *CommandResult {
	var cmd *exec.Cmd
	var outbuf, errbuf bytes.Buffer

	opts := getOpts(opt...)

	if opts.withArgs == nil {
		cmd = exec.CommandContext(ctx, command)
	} else {
		cmd = exec.CommandContext(ctx, command, opts.withArgs...)
	}

	if opts.withEnv != nil {
		cmd.Env = os.Environ()
		for k, v := range opts.withEnv {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
	}

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
// for the provided command. This option can be used multiple times in one command.
//
//	RunCommand(context.Background(), "ls", WithArgs("-al"))
func WithArgs(args ...string) Option {
	return func(o *options) {
		if o.withArgs == nil {
			o.withArgs = args
		} else {
			o.withArgs = append(o.withArgs, args...)
		}
	}
}

// WithEnv is an option to RunCommand that allows the user to specify environment variables
// to be set when running the command. This option can be used multiple times in one command.
//
//	RunCommand(context.Background(), "ls", WithEnv("NAME", "VALUE"), WithEnv("NAME", "VALUE"))
func WithEnv(name string, value string) Option {
	return func(o *options) {
		if o.withEnv == nil {
			o.withEnv = map[string]string{name: value}
		} else {
			o.withEnv[name] = value
		}
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
