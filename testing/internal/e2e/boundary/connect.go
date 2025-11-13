// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package boundary

import (
	"bufio"
	"context"
	"encoding/json"
	"os/exec"
	"testing"

	"github.com/creack/pty"
	"github.com/stretchr/testify/require"
)

// ConnectCli uses the boundary CLI to establish connection to the target.
// It then parses proxy details from the command output and returns them.
// The connection must be closed separately via the `boundary sessions cancel` command
func ConnectCli(t testing.TB, ctx context.Context, targetId string) ConnectCliOutput {
	cmd := exec.CommandContext(ctx,
		"boundary", "connect",
		"-target-id", targetId,
		"-format", "json",
	)
	fileConnect, err := pty.Start(cmd)
	require.NoError(t, err)
	t.Cleanup(func() {
		err := fileConnect.Close()
		require.NoError(t, err)
	})

	scanner := bufio.NewScanner(fileConnect)
	var connectCliOutputJson string
	if scanner.Scan() {
		connectCliOutputJson = scanner.Text()
	}
	require.NoError(t, scanner.Err())

	var connectCliOutput ConnectCliOutput
	err = json.Unmarshal([]byte(connectCliOutputJson), &connectCliOutput)
	require.NoError(t, err)

	return connectCliOutput
}

// ConnectCliStdoutPipe uses the boundary CLI to establish connection to the target.
// It captures stdout via a pipe, parses proxy details from the command output, and returns them.
// The connection must be closed separately via the `boundary sessions cancel` command
// This implementation works on cross platforms (Windows, Unix, Linux, macOS) - unlike the pty-based version above (Unix, Linux, macOS).
// StdoutPipe only captures stdout, as opposed to pty which is an interactive pseudo-terminal
func ConnectCliStdoutPipe(t testing.TB, ctx context.Context, targetId string) ConnectCliOutput {
	cmd := exec.CommandContext(ctx,
		"boundary", "connect",
		"-target-id", targetId,
		"-format", "json",
	)

	// Capture stdout
	stdoutPipe, err := cmd.StdoutPipe()
	require.NoError(t, err)

	// Start the command
	err = cmd.Start()
	require.NoError(t, err)

	// Register cleanup to kill the process
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	})

	// TODO: this doesnt work, need to revist
	// Read lines until we find valid JSON
	scanner := bufio.NewScanner(stdoutPipe)
	var connectOutput ConnectCliOutput
	linesRead := 0
	maxLines := 50

	// Potential issue: trying to scan before session is fully established, and output is written
	// May need a time buffer, instead of loop
	// 1st scanner.Scan() returns true for first line, when session is created
	// 2nd scanner.Scan() - hangs here, cause its waiting for more output, but session is just opended, and not writing any data

	// Example log output:
	// connect.go:83: scan result: true
	// connect.go:85: line 1
	// connect.go:86: outputLine: {"address":"...","port":...,"protocol":"rdp","expiration":"...","connection_limit":-1,"session_id":"..."}
	// hangs on 2nd scan, because no more output is written
	for scanner.Scan() && linesRead < maxLines {
		linesRead++
		outputLine := scanner.Text()

		// Try to parse as JSON
		err = json.Unmarshal([]byte(outputLine), &connectOutput)
		if err == nil {
			break
		}

	}

	require.NoError(t, scanner.Err())
	require.NotEmpty(t, connectOutput.Address)
	require.NotZero(t, connectOutput.Port)

	return connectOutput
}
