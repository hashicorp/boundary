// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package base_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"testing"

	"github.com/creack/pty"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/require"
)

// TestCliAuthenticatePrimary tests the `boundary authenticate` command to ensure that a user can
// more quickly log in using the short-hand form of the command (authenticates using the primary auth
// method).
func TestCliAuthenticatePrimary(t *testing.T) {
	e2e.MaybeSkipTest(t)

	bc, err := boundary.LoadConfig()
	require.NoError(t, err)

	var cmd *exec.Cmd
	ctx := context.Background()
	cmd = exec.CommandContext(ctx, "boundary", "authenticate", "-addr", bc.Address, "-format", "json")

	f, err := pty.Start(cmd)
	require.NoError(t, err)
	t.Cleanup(func() {
		err := f.Close()
		require.NoError(t, err)
	})

	f.Write([]byte(bc.AdminLoginName + "\n"))
	f.Write([]byte(bc.AdminLoginPassword + "\n"))
	f.Write([]byte{4}) // EOT (End of Transmission - marks end of file stream)

	// Get last line from output (authentication response)
	var buf bytes.Buffer
	io.Copy(&buf, f)
	parts := strings.Split(strings.TrimSpace(buf.String()), "\r\n")
	response := parts[len(parts)-1]

	var authenticationResult boundary.AuthenticateCliOutput
	err = json.Unmarshal([]byte(response), &authenticationResult)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, authenticationResult.StatusCode, response)
	token := authenticationResult.Item.Attributes["token"].(string)
	require.NotEmpty(t, token)

	// Use the token
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"users", "list",
			"-token", "env://BOUNDARY_TOKEN",
			"-format", "json",
		),
		e2e.WithEnv("BOUNDARY_TOKEN", token),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// Log out
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs("logout"),
		e2e.WithEnv("BOUNDARY_TOKEN", token),
	)
	// require.NoError(t, output.Err, string(output.Stderr)) // !! It errors here

	// Confirm that token cannot be used
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"users", "list",
			"-token", "env://BOUNDARY_TOKEN",
			"-format", "json",
		),
		e2e.WithEnv("BOUNDARY_TOKEN", token),
	)
	t.Log(string(output.Stdout))
	require.Error(t, output.Err, string(output.Stderr))
}
