// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package base_test

import (
	"context"
	"io"
	"net/url"
	"os/exec"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/hashicorp/boundary/testing/internal/e2e/infra"
	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/require"
)

type redisContainerInfo struct {
	Hostname string
	Port     string
	Username string
	Password string
}

func TestCliTcpTargetConnectRedis(t *testing.T) {
	e2e.MaybeSkipTest(t)

	ctx := context.Background()
	redisInfo := setupRedisContainer(t, ctx)

	cases := []struct {
		name             string
		expectedUsername string
		extraSetup       func(t *testing.T, ctx context.Context, resources *boundaryResources, redisInfo *redisContainerInfo)
	}{
		{
			name:             "UsernamePassword",
			expectedUsername: redisInfo.Username,
			extraSetup: func(t *testing.T, ctx context.Context, resources *boundaryResources, redisInfo *redisContainerInfo) {
				credentialId, err := boundary.CreateStaticCredentialUsernamePasswordCli(
					t,
					ctx,
					resources.storeId,
					redisInfo.Username,
					redisInfo.Password,
				)
				require.NoError(t, err)

				err = boundary.AddBrokeredCredentialSourceToTargetCli(t, ctx, resources.targetId, credentialId)
				require.NoError(t, err)
			},
		},
		{
			name:             "Password",
			expectedUsername: "default",
			extraSetup: func(t *testing.T, ctx context.Context, resources *boundaryResources, redisInfo *redisContainerInfo) {
				credentialId, err := boundary.CreateStaticCredentialPasswordCli(
					t,
					ctx,
					resources.storeId,
					redisInfo.Password,
				)
				require.NoError(t, err)

				err = boundary.AddBrokeredCredentialSourceToTargetCli(t, ctx, resources.targetId, credentialId)
				require.NoError(t, err)
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Setup
			resources := setupBoundaryCredentialStore(t, ctx, redisInfo.Hostname, redisInfo.Port)
			c.extraSetup(t, ctx, resources, redisInfo)

			// Flush redis between tests
			t.Cleanup(func() {
				flushRedis(t, ctx, resources.targetId)
			})

			// Validation
			cmd := exec.CommandContext(ctx,
				"boundary",
				"connect", "redis",
				"-target-id", resources.targetId,
			)

			stdin, err := cmd.StdinPipe()
			require.NoError(t, err)
			stdout, err := cmd.StdoutPipe()
			require.NoError(t, err)
			require.NoError(t, cmd.Start())

			output, err := sendRedisCommand(stdin, stdout, "ACL WHOAMI\r\n")
			require.NoError(t, err)
			require.Equal(t, c.expectedUsername, output)

			output, err = sendRedisCommand(stdin, stdout, "SET e2etestkey e2etestvalue\r\n")
			require.NoError(t, err)
			require.Equal(t, "OK", output)

			output, err = sendRedisCommand(stdin, stdout, "GET e2etestkey\r\n")
			require.NoError(t, err)
			require.Equal(t, "e2etestvalue", output)

			output, err = sendRedisCommand(stdin, stdout, "GET e2etestkey\r\n")
			require.NoError(t, err)
			require.Equal(t, "e2etestvalue", output)

			output, err = sendRedisCommand(stdin, stdout, "QUIT\r\n")
			require.Equal(t, io.EOF, err)
			require.Empty(t, output)

			// Confirm that boundary connect has closed
			err = cmd.Wait()
			require.NoError(t, err)
		})
	}
}

// setupRedisContainer starts a Redis container and returns its connection info
func setupRedisContainer(t *testing.T, ctx context.Context) *redisContainerInfo {
	pool, err := dockertest.NewPool("")
	require.NoError(t, err)

	network, err := pool.NetworksByName("e2e_cluster")
	require.NoError(t, err, "Failed to get e2e_cluster network")

	c := infra.StartRedis(t, pool, &network[0], "redis", "latest")
	require.NotNil(t, c, "Redis container should not be nil")
	t.Cleanup(func() {
		if err := pool.Purge(c.Resource); err != nil {
			t.Logf("Failed to purge Redis container: %v", err)
		}
	})

	u, err := url.Parse(c.UriNetwork)
	t.Log(u)
	require.NoError(t, err, "Failed to parse Redis URL")

	user, hostname, port := u.User.Username(), u.Hostname(), u.Port()
	pw, pwSet := u.User.Password()

	t.Logf("Redis info: user=%s, host=%s, port=%s, password-set:%t",
		user, hostname, port, pwSet)

	// Wait for Redis to be ready
	err = pool.Retry(func() error {
		out, e := exec.CommandContext(ctx, "docker", "exec", hostname,
			"redis-cli", "-h", hostname, "-p", port, "-a", pw, "PING").CombinedOutput()
		t.Logf("Redis PING output: %s", out)
		return e
	})
	require.NoError(t, err, "Redis container failed to start")
	return &redisContainerInfo{
		Hostname: hostname,
		Port:     port,
		Username: user,
		Password: pw,
	}
}

func flushRedis(t *testing.T, ctx context.Context, boundaryTargetId string) {
	cmd := exec.CommandContext(ctx,
		"boundary",
		"connect", "redis",
		"-target-id", boundaryTargetId,
	)

	stdin, err := cmd.StdinPipe()
	require.NoError(t, err)
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())

	output, err := sendRedisCommand(stdin, stdout, "FLUSHALL\r\n")
	require.NoError(t, err)
	require.Equal(t, "OK", output)

	output, err = sendRedisCommand(stdin, stdout, "QUIT\r\n")
	require.Equal(t, io.EOF, err)
	require.Empty(t, output)

	err = cmd.Wait()
	require.NoError(t, err)
}

func sendRedisCommand(stdin io.WriteCloser, stdout io.ReadCloser, cmdStr string) (string, error) {
	_, err := stdin.Write([]byte(cmdStr))
	if err != nil {
		return "", err
	}
	buf := make([]byte, 1024)
	n, err := stdout.Read(buf)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(buf[:n])), nil
}
