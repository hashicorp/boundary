// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package base_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/require"
)

// TestCliUnauthenticatedUserAccess tests that a user that is not logged in is unable to
// run commands that require authentication
func TestCliUnauthenticatedUserAccess(t *testing.T) {
	e2e.MaybeSkipTest(t)

	ctx := t.Context()
	boundary.AuthenticateAdminCli(t, ctx)

	// Check one authenticated request
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"targets", "list",
			"--recursive",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// Logout
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"logout",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// Attempt commands that unauthenticated users can make
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"scopes", "list",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"auth-methods", "list",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// Check user cannot make requests that require authentication
	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"targets", "list",
			"--recursive",
			"-format", "json",
		),
	)
	require.Error(t, output.Err, "Unauthenticated user was able to access private resource")
	fmtError := strings.Split(string(output.Stderr), "\n")[2]
	var response boundary.CliError
	err := json.Unmarshal([]byte(fmtError), &response)
	require.NoError(t, err)
	require.Equal(t, http.StatusForbidden, int(response.Status), "Incorrect error code was returned")

	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"sessions", "list",
			"--recursive",
			"-format", "json",
		),
	)
	require.Error(t, output.Err, "Unauthenticated user was able to access private resource")
	fmtError = strings.Split(string(output.Stderr), "\n")[2]
	err = json.Unmarshal([]byte(fmtError), &response)
	require.NoError(t, err)
	require.Equal(t, http.StatusForbidden, int(response.Status), "Incorrect error code was returned")

	output = e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"users", "list",
			"--recursive",
			"-format", "json",
		),
	)
	require.Error(t, output.Err, "Unauthenticated user was able to access private resource")
	fmtError = strings.Split(string(output.Stderr), "\n")[2]
	err = json.Unmarshal([]byte(fmtError), &response)
	require.NoError(t, err)
	require.Equal(t, http.StatusForbidden, int(response.Status), "Incorrect error code was returned")
}
