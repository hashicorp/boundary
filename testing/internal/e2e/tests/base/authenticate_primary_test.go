// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

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
	require.NotEmpty(t, authenticationResult.Item.Attributes["token"])
}
