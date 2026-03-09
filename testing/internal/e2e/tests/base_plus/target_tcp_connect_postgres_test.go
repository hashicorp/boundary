// Copyright IBM Corp. 2020, 2025
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
	targetId, err := boundary.CreateTargetCli(
		t,
		ctx,
		projectId,
		c.PostgresPort,
		[]target.Option{target.WithAddress(c.PostgresAddress)},
	)
	require.NoError(t, err)
	storeId, err := boundary.CreateCredentialStoreStaticCli(t, ctx, projectId)
	require.NoError(t, err)
	credentialId, err := boundary.CreateStaticCredentialUsernamePasswordCli(
		t,
		ctx,
		storeId,
		c.PostgresUser,
		c.PostgresPassword,
	)
	require.NoError(t, err)
	err = boundary.AddBrokeredCredentialSourceToTargetCli(t, ctx, targetId, credentialId)
	require.NoError(t, err)

	cmd := exec.CommandContext(ctx,
		"boundary",
		"connect", "postgres",
		"-target-id", targetId,
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
