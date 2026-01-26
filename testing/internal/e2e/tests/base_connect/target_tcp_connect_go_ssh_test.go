// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package base_connect_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// TestCliTcpTargetConnectGoSsh uses the go experimental ssh library to connect to a target
func TestCliTcpTargetConnectGoSsh(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadTestConfig()
	require.NoError(t, err)

	ctx := t.Context()
	boundary.AuthenticateAdminCli(t, ctx)
	orgId, err := boundary.CreateOrgCli(t, ctx)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx := context.Background()
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary", e2e.WithArgs("scopes", "delete", "-id", orgId))
		require.NoError(t, output.Err, string(output.Stderr))
	})
	projectId, err := boundary.CreateProjectCli(t, ctx, orgId)
	require.NoError(t, err)
	targetId, err := boundary.CreateTargetCli(t, ctx, projectId, c.TargetPort, []target.Option{target.WithAddress(c.TargetAddress)})
	require.NoError(t, err)

	// Start a session
	ctxCancel, cancel := context.WithCancel(context.Background())
	port := "12345"
	cmdChan := make(chan *e2e.CommandResult)
	go func() {
		t.Log("Starting session...")
		cmdChan <- e2e.RunCommand(ctxCancel, "boundary",
			e2e.WithArgs(
				"connect",
				"-target-id", targetId,
				"-listen-port", port,
				"-format", "json",
			),
		)
	}()
	t.Cleanup(cancel)

	boundary.WaitForSessionCli(t, ctx, projectId, nil)

	// Connect to the target using the go experimental ssh library
	privateKeyRaw, err := os.ReadFile(c.TargetSshKeyPath)
	require.NoError(t, err)
	signer, err := ssh.ParsePrivateKey(privateKeyRaw)
	require.NoError(t, err)

	config := &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		User:            c.TargetSshUser,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
	}
	client, err := ssh.Dial("tcp", fmt.Sprintf("localhost:%s", port), config)
	require.NoError(t, err)
	t.Cleanup(func() { client.Close() })

	// Run a command and validate its output
	session, err := client.NewSession()
	require.NoError(t, err)
	t.Cleanup(func() { session.Close() })
	output, err := session.CombinedOutput("hostname -i")
	require.NoError(t, err, string(output))
	require.Equal(t, c.TargetAddress, strings.TrimSpace(string(output)))

	// Run a command and expect an error
	sessionWithError, err := client.NewSession()
	require.NoError(t, err)
	t.Cleanup(func() { sessionWithError.Close() })
	output, err = sessionWithError.CombinedOutput("rm test.txt")
	require.Error(t, err, string(output))
}
