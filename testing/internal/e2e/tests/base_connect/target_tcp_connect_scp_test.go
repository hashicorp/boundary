// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package base_connect_test

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/require"
)

// TestCliTcpTargetConnectTargetAndScp connects to a target and validates scp
// operations by uploading and downloading a file to a host and verifies that
// checksums match
func TestCliTcpTargetConnectTargetAndScp(t *testing.T) {
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
		c.TargetPort,
		[]target.Option{target.WithAddress(c.TargetAddress)},
	)
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

	// Create file to scp
	testDir := t.TempDir()
	t.Log("Creating text file...")
	fileSource := fmt.Sprintf("%s/%s_src.txt", testDir, t.Name())
	f, err := os.Create(fileSource)
	require.NoError(t, err)
	_, err = io.CopyN(f, rand.Reader, 256000)
	require.NoError(t, err)

	fi, err := f.Stat()
	require.NoError(t, err)
	require.Greater(t, fi.Size(), int64(16000), "Generated file is not larger than 16K")

	output := e2e.RunCommand(ctx, "cksum", e2e.WithArgs(fileSource))
	require.NoError(t, output.Err, string(output.Stderr))
	parts := strings.Fields(string(output.Stdout))
	cksumSource := parts[0]

	// Copy file to host
	t.Log("Copying file to host...")
	fileUpload := fmt.Sprintf("/tmp/%s_upload.txt", t.Name())
	output = e2e.RunCommand(ctx, "scp",
		e2e.WithArgs(
			"-i", c.TargetSshKeyPath,
			"-P", port,
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "StrictHostKeyChecking=no",
			"-o", "IdentitiesOnly=yes", // forces the use of the provided key
			fileSource,
			fmt.Sprintf("%s@localhost:%s", c.TargetSshUser, fileUpload),
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// Validate checksum
	output = e2e.RunCommand(ctx, "ssh",
		e2e.WithArgs(
			"localhost",
			"-p", port,
			"-l", c.TargetSshUser,
			"-i", c.TargetSshKeyPath,
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "StrictHostKeyChecking=no",
			"-o", "IdentitiesOnly=yes", // forces the use of the provided key
			fmt.Sprintf("cksum %s", fileUpload),
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))
	parts = strings.Fields(string(output.Stdout))
	cksumUpload := parts[0]
	require.Equal(t, cksumSource, cksumUpload, "Checksum of uploaded file does not match source")

	// Read file on host
	t.Log("Reading file on host...")
	output = e2e.RunCommand(ctx, "ssh",
		e2e.WithArgs(
			"localhost",
			"-p", port,
			"-l", c.TargetSshUser,
			"-i", c.TargetSshKeyPath,
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "StrictHostKeyChecking=no",
			"-o", "IdentitiesOnly=yes", // forces the use of the provided key
			fmt.Sprintf("cat %s", fileUpload),
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// Download file from host
	t.Log("Downloading file from host...")
	fileDownload := fmt.Sprintf("%s/%s_download.txt", testDir, t.Name())
	output = e2e.RunCommand(ctx, "scp",
		e2e.WithArgs(
			"-i", c.TargetSshKeyPath,
			"-P", port,
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "StrictHostKeyChecking=no",
			"-o", "IdentitiesOnly=yes", // forces the use of the provided key
			fmt.Sprintf("%s@localhost:%s", c.TargetSshUser, fileUpload),
			fileDownload,
		),
	)
	require.NoError(t, output.Err, string(output.Stderr))

	// Validate checksum
	output = e2e.RunCommand(ctx, "cksum", e2e.WithArgs(fileDownload))
	require.NoError(t, output.Err, string(output.Stderr))
	parts = strings.Fields(string(output.Stdout))
	cksumDownload := parts[0]
	require.Equal(t, cksumSource, cksumDownload, "Checksum of downloaded file does not match source")
}
