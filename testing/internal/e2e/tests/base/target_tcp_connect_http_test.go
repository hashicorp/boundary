// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package base_test

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"testing"

	"github.com/creack/pty"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/require"
)

// TestCliTcpTargetConnectHttp validates the usage of "boundary connect http".
// This is done by first connecting to an SSH target, starting a webserver on
// that target, and then creating another target that connects to the webserver
func TestCliTcpTargetConnectHttp(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadTestConfig()
	require.NoError(t, err)

	ctx := context.Background()
	boundary.AuthenticateAdminCli(t, ctx)
	orgId, err := boundary.CreateOrgCli(t, ctx)
	require.NoError(t, err)
	t.Cleanup(func() {
		output := e2e.RunCommand(ctx, "boundary", e2e.WithArgs("scopes", "delete", "-id", orgId))
		require.NoError(t, output.Err, string(output.Stderr))
	})
	projectId, err := boundary.CreateProjectCli(t, ctx, orgId)
	require.NoError(t, err)
	targetId, err := boundary.CreateTargetCli(t, ctx, projectId, c.TargetPort, target.WithAddress(c.TargetAddress))
	require.NoError(t, err)
	storeId, err := boundary.CreateCredentialStoreStaticCli(t, ctx, projectId)
	require.NoError(t, err)
	credentialId, err := boundary.CreateStaticCredentialPrivateKeyCli(t, ctx, storeId, c.TargetSshUser, c.TargetSshKeyPath)
	require.NoError(t, err)
	err = boundary.AddBrokeredCredentialSourceToTargetCli(t, ctx, targetId, credentialId)
	require.NoError(t, err)

	// Connect to a target and enable port forwarding
	localPort := "8080"
	destPort := "8000"
	var cmd *exec.Cmd
	cmd = exec.CommandContext(ctx,
		"boundary",
		"connect", "ssh",
		"-target-id", targetId, "--",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "StrictHostKeyChecking=no",
		"-L", fmt.Sprintf("%s:localhost:%s", localPort, destPort),
	)
	f, err := pty.Start(cmd)
	require.NoError(t, err)
	t.Cleanup(func() {
		err := f.Close()
		require.NoError(t, err)
	})

	t.Log("Starting a webserver on the target...")
	htmlPage := "<html>Hello World!</html>"
	go func() {
		_, err = f.Write([]byte(fmt.Sprintf("echo '%s' > somepage.html\n", htmlPage)))
		require.NoError(t, err)
		_, err = f.Write([]byte(fmt.Sprintf("while true; do nc -l -p %s -q 1 < somepage.html; done\n", destPort)))
		require.NoError(t, err)
		_, _ = io.Copy(io.Discard, f) // Not checking error here since it fails in CI for some reason
	}()

	s := boundary.WaitForSessionCli(t, ctx, projectId)
	boundary.WaitForSessionStatusCli(t, ctx, s.Id, session.StatusActive.String())

	// Create http target and connect to it
	httpTargetId, err := boundary.CreateTargetCli(t, ctx, projectId, destPort, target.WithAddress(c.TargetAddress))
	require.NoError(t, err)
	output := e2e.RunCommand(ctx, "boundary",
		e2e.WithArgs(
			"connect", "http",
			"-target-id", httpTargetId,
			"-scheme", "http",
			"--",
			"--http0.9",
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	require.Contains(t, string(output.Stdout), htmlPage)
}
