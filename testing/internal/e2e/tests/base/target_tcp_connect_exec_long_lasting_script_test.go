// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package base_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/require"
)

// TestCliTcpTargetConnectExecLongLastingScript verifies that SSH requests sent to TCP target
// can execute long-lasting scripts successfully.
// It sends two SSH requests:
// - to execute the script saved on the target
// - to execute the script sent with the SSH request
func TestCliTcpTargetConnectExecLongLastingScript(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadTestConfig()
	require.NoError(t, err)

	ctx := context.Background()
	boundary.AuthenticateAdminCli(t, ctx)

	// Create test organization
	newOrgId := boundary.CreateNewOrgCli(t, ctx)

	// Delete organization after the test is completed
	t.Cleanup(func() {
		ctx := context.Background()
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary", e2e.WithArgs("scopes", "delete", "-id", newOrgId))
		require.NoError(t, output.Err, string(output.Stderr))
	})
	// Create test project
	newProjectId := boundary.CreateNewProjectCli(t, ctx, newOrgId)

	// Create static credentials
	newCredentialStoreId := boundary.CreateNewCredentialStoreStaticCli(t, ctx, newProjectId)
	newCredentialsId := boundary.CreateNewStaticCredentialPrivateKeyCli(t, ctx, newCredentialStoreId, c.TargetSshUser, c.TargetSshKeyPath)

	// Create TCP target
	newTargetId := boundary.CreateNewTargetCli(t, ctx, newProjectId, c.TargetPort,
		target.WithType("tcp"),
		target.WithAddress(c.TargetAddress),
	)
	boundary.AddBrokeredCredentialSourceToTargetCli(t, ctx, newTargetId, newCredentialsId)

	// Start a session
	ctxCancel, cancel := context.WithCancel(context.Background())
	proxyPort := "12345"
	cmdChan := make(chan *e2e.CommandResult)
	go func() {
		t.Log("Starting session...")
		cmdChan <- e2e.RunCommand(ctxCancel, "boundary",
			e2e.WithArgs(
				"connect",
				"-target-id", newTargetId,
				"-listen-port", proxyPort,
				"-format", "json",
			),
		)
	}()
	t.Cleanup(cancel)
	boundary.WaitForSessionCli(t, ctx, newProjectId)

	t.Log("Copying script to host...")
	output := e2e.RunCommand(ctx, "scp",
		e2e.WithArgs(
			"-i", c.TargetSshKeyPath,
			"-P", proxyPort,
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "StrictHostKeyChecking=no",
			"-o", "IdentitiesOnly=yes", // forces the use of the provided key
			"testdata/long_lasting_test_script.sh",
			fmt.Sprintf("%s@localhost:%s", c.TargetSshUser, "long_lasting_test_script.sh"),
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// Send SSH requests to the target to execute long-lasting scripts
	t.Log("Executing the long-lasting script saved on the target...")
	output = e2e.RunCommand(ctx, "ssh",
		e2e.WithArgs(
			"-v",
			"-l", c.TargetSshUser,
			"-i", c.TargetSshKeyPath,
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "StrictHostKeyChecking=no",
			"-p", proxyPort,
			"localhost",
			"./long_lasting_test_script.sh"),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	t.Log("Executing a long-lasting script sent with the ssh request...")
	output = e2e.RunCommand(ctx, "ssh",
		e2e.WithArgs(
			"-v",
			"-l", c.TargetSshUser,
			"-i", c.TargetSshKeyPath,
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "StrictHostKeyChecking=no",
			"-p", proxyPort,
			"localhost",
			"sleep 5"),
	)
	require.NoError(t, output.Err, string(output.Stderr))
}
