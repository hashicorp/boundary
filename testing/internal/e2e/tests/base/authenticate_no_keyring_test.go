// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package base_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/require"
)

// TestCliAuthenticateNoKeyring tests authentication when we're using `-format
// json` and there is no keyring on the system.
// This covers a case where the client cache daemon should intercept the auth
// token in the json response. There was previously a bug where the client cache
// daemon tried to access the keyring when there wasn't one on the system.
func TestCliAuthenticateNoKeyring(t *testing.T) {
	e2e.MaybeSkipTest(t)
	ctx := t.Context()

	bc, err := boundary.LoadConfig()
	require.NoError(t, err)

	containerID := "boundary"

	docker, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	require.NoError(t, err)

	// Check that `pass` is not in the docker container
	execConfig := container.ExecOptions{
		AttachStdout: true,
		AttachStderr: true,
		Cmd: []string{
			"which", "pass",
		},
	}
	exec, err := docker.ContainerExecCreate(ctx, containerID, execConfig)
	require.NoError(t, err)
	resp, err := docker.ContainerExecAttach(ctx, exec.ID, container.ExecAttachOptions{})
	require.NoError(t, err)
	t.Cleanup(func() {
		resp.Close()
	})

	var outBuf, errBuf bytes.Buffer
	outputDone := make(chan error)
	go func() {
		// StdCopy demultiplexes the stream into two buffers
		_, err = stdcopy.StdCopy(&outBuf, &errBuf, resp.Reader)
		outputDone <- err
	}()

	select {
	case err := <-outputDone:
		if err != nil {
			require.NoError(t, err)
		}
		break

	case <-ctx.Done():
		require.NoError(t, ctx.Err())
	}

	stdout, err := io.ReadAll(&outBuf)
	require.NoError(t, err)
	require.Empty(t, string(stdout))

	// Try to authenticate from inside the docker container
	execConfig = container.ExecOptions{
		AttachStdout: true,
		AttachStderr: true,
		Cmd: []string{
			"boundary", "authenticate", "password",
			"-login-name", bc.AdminLoginName,
			"-password", "env://E2E_PASSWORD",
			"-format", "json",
		},
		Env: []string{
			fmt.Sprintf("BOUNDARY_ADDR=%s", bc.Address),
			fmt.Sprintf("E2E_PASSWORD=%s", bc.AdminLoginPassword),
		},
	}
	exec, err = docker.ContainerExecCreate(ctx, containerID, execConfig)
	require.NoError(t, err)
	authResp, err := docker.ContainerExecAttach(ctx, exec.ID, container.ExecAttachOptions{})
	require.NoError(t, err)
	t.Cleanup(func() {
		authResp.Close()
	})

	outBuf.Reset()
	errBuf.Reset()
	go func() {
		_, err = stdcopy.StdCopy(&outBuf, &errBuf, authResp.Reader)
		outputDone <- err
	}()

	select {
	case err := <-outputDone:
		if err != nil {
			require.NoError(t, err)
		}
		break

	case <-ctx.Done():
		require.NoError(t, ctx.Err())
	}

	stdout, err = io.ReadAll(&outBuf)
	require.NoError(t, err)
	require.NotEmpty(t, string(stdout))
	stderr, err := io.ReadAll(&errBuf)
	require.NoError(t, err)
	require.Empty(t, string(stderr))

	var authenticationResult boundary.AuthenticateCliOutput
	err = json.Unmarshal(stdout, &authenticationResult)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, authenticationResult.StatusCode, string(stdout))
	require.NotEmpty(t, authenticationResult.Item.Attributes["token"])
}
