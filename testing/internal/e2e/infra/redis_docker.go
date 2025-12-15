// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package infra

import (
	"fmt"
	"io"
	"net/url"
	"os/exec"
	"strings"
	"testing"

	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/require"
)

type RedisContainerInfo struct {
	Hostname string
	Port     string
	Username string
	Password string
}

type redisConfig struct {
	User         string
	Password     string
	NetworkAlias string
}

// SetupRedisContainer starts a Redis container and returns its connection info
func SetupRedisContainer(t *testing.T) *RedisContainerInfo {
	pool, err := dockertest.NewPool("")
	require.NoError(t, err)

	network, err := pool.NetworksByName("e2e_cluster")
	require.NoError(t, err, "Failed to get e2e_cluster network")

	c := startRedis(t, pool, &network[0], "redis", "latest")
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

	return &RedisContainerInfo{
		Hostname: hostname,
		Port:     port,
		Username: user,
		Password: pw,
	}
}

// startRedis starts a Redis database in a docker container.
// Returns information about the container
func startRedis(t testing.TB, pool *dockertest.Pool, network *dockertest.Network, repository, tag string) *Container {
	t.Log("Starting Redis database...")
	c, err := LoadConfig()
	require.NoError(t, err)

	err = pool.Client.PullImage(docker.PullImageOptions{
		Repository: fmt.Sprintf("%s/%s", c.DockerMirror, repository),
		Tag:        tag,
	}, docker.AuthConfiguration{})
	require.NoError(t, err)

	config := redisConfig{
		User:         "e2eboundary",
		Password:     "e2eboundary",
		NetworkAlias: "e2eredis",
	}

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository:   fmt.Sprintf("%s/%s", c.DockerMirror, repository),
		Tag:          tag,
		ExposedPorts: []string{"6379/tcp"},
		Name:         config.NetworkAlias,
		Networks:     []*dockertest.Network{network},
	})
	require.NoError(t, err)

	err = pool.Retry(func() error {
		cmd := exec.Command("docker", "exec", config.NetworkAlias, "redis-cli", "PING")
		output, cmdErr := cmd.CombinedOutput()
		if cmdErr != nil {
			return fmt.Errorf("failed to connect to Redis container '%s': %v\nOutput: %s", config.NetworkAlias, cmdErr, string(output))
		}
		return nil
	})
	require.NoError(t, err, "Redis container did not start in time or is not healthy")

	// configure redis users
	// e2e user
	err = exec.Command(
		"docker", "exec", config.NetworkAlias, "redis-cli",
		"ACL", "SETUSER", config.User, "on", fmt.Sprintf(">%s", config.Password), "+@all", "allkeys",
	).Run()
	require.NoError(t, err)

	// default user
	err = exec.Command(
		"docker", "exec", config.NetworkAlias, "redis-cli",
		"ACL", "SETUSER", "default", fmt.Sprintf(">%s", config.Password),
	).Run()
	require.NoError(t, err)

	return &Container{
		Resource: resource,
		UriLocalhost: fmt.Sprintf(
			"redis://%s:%s@localhost:6379",
			config.User,
			config.Password,
		),
		UriNetwork: fmt.Sprintf(
			"redis://%s:%s@%s:6379",
			config.User,
			config.Password,
			config.NetworkAlias,
		),
	}
}

func SendRedisCommand(stdin io.WriteCloser, stdout io.ReadCloser, cmdStr string) (string, error) {
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
