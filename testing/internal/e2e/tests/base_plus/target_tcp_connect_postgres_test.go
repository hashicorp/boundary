// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package base_plus_test

import (
	"bytes"
	"context"
	"io"
	"os/exec"
	"testing"

	"github.com/creack/pty"
	"github.com/stretchr/testify/require"

	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
)

// TestCliTcpTargetConnectPostgres uses the boundary cli to connect to a
// target using `connect postgres`
func TestCliTcpTargetConnectPostgres(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadTestConfig()
	require.NoError(t, err)

	ctx := context.Background()
	boundary.AuthenticateAdminCli(t, ctx)
	orgId, err := boundary.CreateOrgCli(t, ctx)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx := context.Background()
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary", e2e.WithArgs("scopes", "delete", "-id", orgId))
		require.NoError(t, output.Err, string(output.Stderr))
	})
	newProjectId := boundary.CreateNewProjectCli(t, ctx, orgId)
	newTargetId := boundary.CreateNewTargetCli(
		t,
		ctx,
		newProjectId,
		c.TargetPort,
		target.WithAddress(c.TargetAddress),
	)
	newCredentialStoreId := boundary.CreateNewCredentialStoreStaticCli(t, ctx, newProjectId)
	newCredentialsId := boundary.CreateNewStaticCredentialPasswordCli(
		t,
		ctx,
		newCredentialStoreId,
		c.PostgresUser,
		c.PostgresPassword,
	)
	boundary.AddBrokeredCredentialSourceToTargetCli(t, ctx, newTargetId, newCredentialsId)

	var cmd *exec.Cmd
	cmd = exec.CommandContext(ctx,
		"boundary",
		"connect", "postgres",
		"-target-id", newTargetId,
		"-dbname", c.PostgresDbName,
	)
	f, err := pty.Start(cmd)
	require.NoError(t, err)
	t.Cleanup(func() {
		err := f.Close()
		require.NoError(t, err)
	})

	_, err = f.Write([]byte("\\pset pager off\n")) // disables pagination in output
	require.NoError(t, err)
	_, err = f.Write([]byte("\\dt\n")) // list all tables
	require.NoError(t, err)
	_, err = f.Write([]byte("\\q\n")) // exit psql session
	require.NoError(t, err)
	_, err = f.Write([]byte{4}) // EOT (End of Transmission - marks end of file stream)
	require.NoError(t, err)

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, f)
	require.Contains(t, buf.String(), "List of relations", "Session did not return expected output")
	require.Contains(t, buf.String(), c.PostgresDbName, "Session did not return expected output")
	t.Log("Successfully connected to target")
}
