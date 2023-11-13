// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package base_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
)

// TestCliTcpTargetConnectGolangSsh uses the golang ssh library to connect to a target
func TestCliTcpTargetConnectGolangSsh(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadTestConfig()
	require.NoError(t, err)

	ctx := context.Background()
	boundary.AuthenticateAdminCli(t, ctx)
	newOrgId := boundary.CreateNewOrgCli(t, ctx)
	t.Cleanup(func() {
		ctx := context.Background()
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary", e2e.WithArgs("scopes", "delete", "-id", newOrgId))
		require.NoError(t, output.Err, string(output.Stderr))
	})
	newProjectId := boundary.CreateNewProjectCli(t, ctx, newOrgId)
	newTargetId := boundary.CreateNewTargetCli(t, ctx, newProjectId, c.TargetPort, target.WithAddress(c.TargetAddress))

	// Start a session
	ctxCancel, cancel := context.WithCancel(context.Background())
	port := "12345"
	cmdChan := make(chan *e2e.CommandResult)
	go func() {
		t.Log("Starting session...")
		cmdChan <- e2e.RunCommand(ctxCancel, "boundary",
			e2e.WithArgs(
				"connect",
				"-target-id", newTargetId,
				"-listen-port", port,
				"-format", "json",
			),
		)
	}()
	t.Cleanup(cancel)

	boundary.WaitForSessionCli(t, ctx, newProjectId)

	// Connect to the target using the golang ssh library
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
