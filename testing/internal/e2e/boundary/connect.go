// Copyright IBM Corp. 2020, 2025
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
