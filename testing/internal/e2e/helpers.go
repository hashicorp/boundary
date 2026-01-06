// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package e2e

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"testing"
	"time"
)

// CommandResult captures the output from running an external command
type CommandResult struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
	Err      error
	Duration time.Duration
}

// Option is a func that sets optional attributes for a call. This does not need
// to be used directly, but instead option arguments are built from the
// functions in this package. WithX options set a value to that given in the
// argument; DefaultX options indicate that the value should be set to its
// default. When an API call is made options are processed in the order they
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

const (
	EnvToCheckSkip     = "E2E_TESTS"
	EnvToCheckSlowSkip = "E2E_SLOW_TESTS"
)

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

	startTime := time.Now()
	err := cmd.Run()
	endTime := time.Now()
	duration := endTime.Sub(startTime)

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
		Duration: duration,
	}
}

// RunCommandWithPipe runs a command and captures the first line of output from its stdout pipe.
// This implementation works on cross platforms (Windows, Unix, Linux, macOS) - unlike the pty-based version above (Unix, Linux, macOS).
// StdoutPipe only captures stdout, as opposed to pty which is an interactive pseudo-terminal
func RunCommandWithPipe(t testing.TB, ctx context.Context, command string, opt ...Option) (string, error) {
	ctxCancel, cancel := context.WithCancel(ctx)
	// channels to capture output and errors from goroutine
	outputChan := make(chan string, 1)
	errorChan := make(chan error, 1)

	// Process options
	opts := getOpts(opt...)

	// Build command with args
	var cmd *exec.Cmd
	if opts.withArgs == nil {
		cmd = exec.CommandContext(ctxCancel, command)
	} else {
		cmd = exec.CommandContext(ctxCancel, command, opts.withArgs...)
	}

	// Apply environment variables
	if opts.withEnv != nil {
		cmd.Env = os.Environ()
		for k, v := range opts.withEnv {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
	}

	// Run goroutine in background
	go func() {
		// Capture stdout via pipe
		stdoutPipe, err := cmd.StdoutPipe()
		if err != nil {
			errorChan <- fmt.Errorf("failed to create standard out pipe: %w", err)
			return
		}

		// Start the command (don't wait for it to finish)
		err = cmd.Start()
		if err != nil {
			errorChan <- fmt.Errorf("failed to start command: %w", err)
			return
		}

		// Read first line of output and send to channel
		scanner := bufio.NewScanner(stdoutPipe)
		if scanner.Scan() {
			outputChan <- scanner.Text()
		} else {
			if err := scanner.Err(); err != nil {
				errorChan <- fmt.Errorf("failed read output from pipe: %w", err)
			} else {
				errorChan <- errors.New("no output from command")
			}
		}
		// Command continues running after this as proxy connection is intended to stay open
		// We only need the first line of output

		// Continuously drains the stdout pipe in the background to prevent the command from blocking
		go func() {
			_, _ = io.Copy(io.Discard, stdoutPipe)
		}()
	}()

	// Cleanup kills the process
	t.Cleanup(func() {
		cancel()
	})

	// Return result of goroutine
	select {
	case output := <-outputChan:
		return output, nil
	case err := <-errorChan:
		return "", err
	case <-ctxCancel.Done():
		return "", ctxCancel.Err()
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
		t.Skipf(
			"Skipping test because environment variable %q is not set. This is needed for e2e tests.",
			EnvToCheckSkip,
		)
	}
}

// MaybeSkipSlowTest is a check used at the start of the test to determine if the test should run
func MaybeSkipSlowTest(t testing.TB) {
	MaybeSkipTest(t)
	if _, ok := os.LookupEnv(EnvToCheckSlowSkip); !ok {
		t.Skipf(
			"Skipping test because environment variable %q is not set. This is needed for slow e2e tests.",
			EnvToCheckSlowSkip,
		)
	}
}
