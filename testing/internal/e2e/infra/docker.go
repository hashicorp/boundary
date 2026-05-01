// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package infra

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"testing"

	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// Container stores information about the docker container
type Container struct {
	Resource     *dockertest.Resource
	UriLocalhost string
	UriNetwork   string
}

// cassandraConfig stores configuration details for the Cassandra container
type cassandraConfig struct {
	User         string
	Password     string
	Keyspace     string
	NetworkAlias string
}

// StartBoundaryDatabase spins up a postgres database in a docker container.
// Returns information about the container
func StartBoundaryDatabase(t testing.TB, pool *dockertest.Pool, network *dockertest.Network, repository, tag string) *Container {
	t.Log("Starting postgres database...")
	c, err := LoadConfig()
	require.NoError(t, err)

	err = pool.Client.PullImage(docker.PullImageOptions{
		Repository: fmt.Sprintf("%s/%s", c.DockerMirror, repository),
		Tag:        tag,
	}, docker.AuthConfiguration{})
	require.NoError(t, err)

	networkAlias := "e2epostgres"
	postgresDb := "e2eboundarydb"
	postgresUser := "e2eboundary"
	postgresPassword := "e2eboundary"
	postgresConfigFilePath, err := filepath.Abs("testdata/postgresql.conf")
	require.NoError(t, err)

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: fmt.Sprintf("%s/%s", c.DockerMirror, repository),
		Tag:        tag,
		Cmd:        []string{"postgres", "-c", "config_file=/etc/postgresql/postgresql.conf"},
		Env: []string{
			"POSTGRES_DB=" + postgresDb,
			"POSTGRES_USER=" + postgresUser,
			"POSTGRES_PASSWORD=" + postgresPassword,
		},
		Mounts:       []string{path.Dir(postgresConfigFilePath) + ":/etc/postgresql/"},
		ExposedPorts: []string{"5432/tcp"},
		Name:         networkAlias,
		Networks:     []*dockertest.Network{network},
	})
	require.NoError(t, err)

	return &Container{
		Resource: resource,
		UriLocalhost: fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=disable",
			postgresUser,
			postgresPassword,
			resource.GetHostPort("5432/tcp"),
			postgresDb,
		),
		UriNetwork: fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
			postgresUser,
			postgresPassword,
			networkAlias,
			"5432",
			postgresDb,
		),
	}
}

// InitBoundaryDatabase starts a boundary container (of the latest released version) and initializes a
// postgres database (using `boundary database init`) at the specified postgres URI.
// Returns information about the container
func InitBoundaryDatabase(t testing.TB, pool *dockertest.Pool, network *dockertest.Network, repository, tag, postgresURI string) *Container {
	t.Log("Initializing postgres database...")
	c, err := LoadConfig()
	require.NoError(t, err)

	boundaryConfigFilePath, err := filepath.Abs("testdata/boundary-config.hcl")
	require.NoError(t, err)

	err = pool.Client.PullImage(docker.PullImageOptions{
		Repository: fmt.Sprintf("%s/%s", c.DockerMirror, repository),
		Tag:        tag,
	}, docker.AuthConfiguration{})
	require.NoError(t, err)

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: fmt.Sprintf("%s/%s", c.DockerMirror, repository),
		Tag:        tag,
		Cmd:        []string{"boundary", "database", "init", "-config", "/boundary/boundary-config.hcl", "-format", "json"},
		Env: []string{
			fmt.Sprintf("BOUNDARY_LICENSE=%s", c.BoundaryLicense),
			fmt.Sprintf("BOUNDARY_POSTGRES_URL=%s", postgresURI),
			"SKIP_CHOWN=true",
		},
		Mounts:   []string{path.Dir(boundaryConfigFilePath) + ":/boundary/"},
		Name:     "boundary-init",
		Networks: []*dockertest.Network{network},
		CapAdd:   []string{"IPC_LOCK"},
	})
	require.NoError(t, err)

	return &Container{Resource: resource}
}

// GetDbInitInfoFromContainer extracts info from calling `boundary database init` in the specified
// container.
// Returns a struct containing the generated info.
func GetDbInitInfoFromContainer(t testing.TB, pool *dockertest.Pool, container *Container) boundary.DbInitInfo {
	_, err := pool.Client.WaitContainer(container.Resource.Container.ID)
	require.NoError(t, err)
	buf := bytes.NewBuffer(nil)
	ebuf := bytes.NewBuffer(nil)
	err = pool.Client.Logs(docker.LogsOptions{
		Container:    container.Resource.Container.ID,
		OutputStream: buf,
		ErrorStream:  ebuf,
		Follow:       true,
		Stdout:       true,
		Stderr:       true,
	})
	require.NoError(t, err)
	require.Empty(t, ebuf)

	var dbInitInfo boundary.DbInitInfo
	err = json.Unmarshal(buf.Bytes(), &dbInitInfo)
	require.NoError(t, err, buf.String())

	return dbInitInfo
}

// StartBoundary starts a boundary container and spins up an instance of boundary using the
// specified database at postgresURI.
// Returns information about the container.
func StartBoundary(t testing.TB, pool *dockertest.Pool, network *dockertest.Network, repository, tag, postgresURI string) *Container {
	t.Log("Starting Boundary...")
	c, err := LoadConfig()
	require.NoError(t, err)

	boundaryConfigFilePath, err := filepath.Abs("testdata/boundary-config.hcl")
	require.NoError(t, err)

	err = pool.Client.PullImage(docker.PullImageOptions{
		Repository: fmt.Sprintf("%s/%s", c.DockerMirror, repository),
		Tag:        tag,
	}, docker.AuthConfiguration{})
	require.NoError(t, err)

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: fmt.Sprintf("%s/%s", c.DockerMirror, repository),
		Tag:        tag,
		Cmd:        []string{"boundary", "server", "-config", "/boundary/boundary-config.hcl"},
		Env: []string{
			fmt.Sprintf("BOUNDARY_LICENSE=%s", c.BoundaryLicense),
			fmt.Sprintf("BOUNDARY_POSTGRES_URL=%s", postgresURI),
			"HOSTNAME=boundary",
			"SKIP_CHOWN=true",
		},
		Mounts:       []string{path.Dir(boundaryConfigFilePath) + ":/boundary/"},
		Name:         "boundary",
		Networks:     []*dockertest.Network{network},
		ExposedPorts: []string{"9200/tcp", "9201/tcp", "9202/tcp", "9203/tcp"},
		PortBindings: map[docker.Port][]docker.PortBinding{
			"9200/tcp": {{HostIP: "127.0.0.1", HostPort: "9200"}},
			"9201/tcp": {{HostIP: "127.0.0.1", HostPort: "9201"}},
			"9202/tcp": {{HostIP: "127.0.0.1", HostPort: "9202"}},
			"9203/tcp": {{HostIP: "127.0.0.1", HostPort: "9203"}},
		},
		CapAdd: []string{"IPC_LOCK"},
	})
	require.NoError(t, err)

	return &Container{
		Resource:     resource,
		UriLocalhost: "http://127.0.0.1:9200",
		UriNetwork:   "http://boundary:9200",
	}
}

// StartVault starts a vault container.
// Returns information about the container.
func StartVault(t testing.TB, pool *dockertest.Pool, network *dockertest.Network, repository, tag string) (*Container, string) {
	t.Log("Starting Vault...")
	c, err := LoadConfig()
	require.NoError(t, err)

	err = pool.Client.PullImage(docker.PullImageOptions{
		Repository: fmt.Sprintf("%s/%s", c.DockerMirror, repository),
		Tag:        tag,
	}, docker.AuthConfiguration{})
	require.NoError(t, err)

	vaultToken := "boundarytok"
	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: fmt.Sprintf("%s/%s", c.DockerMirror, repository),
		Tag:        tag,
		Env: []string{
			"VAULT_DEV_ROOT_TOKEN_ID=" + vaultToken,
		},
		Name:         "vault",
		Networks:     []*dockertest.Network{network},
		ExposedPorts: []string{"8200/tcp"},
		PortBindings: map[docker.Port][]docker.PortBinding{
			"8200/tcp": {{HostIP: "127.0.0.1", HostPort: "8210"}},
		},
		CapAdd: []string{"IPC_LOCK"},
	})
	require.NoError(t, err)

	uriLocalhost := "http://127.0.0.1:8210"

	return &Container{
			Resource:     resource,
			UriLocalhost: uriLocalhost,
			UriNetwork:   "http://vault:8200",
		},
		vaultToken
}

// ConnectToTarget starts a boundary container and attempts to connect to the specified target. The
// goal of this method is to create a session entry in the database.
// Returns information about the container.
func ConnectToTarget(t testing.TB, pool *dockertest.Pool, network *dockertest.Network, repository, tag, boundaryAddr, token, targetId string) *Container {
	t.Log("Connecting to target...")
	c, err := LoadConfig()
	require.NoError(t, err)

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: fmt.Sprintf("%s/%s", c.DockerMirror, repository),
		Tag:        tag,
		Cmd: []string{
			"boundary", "connect",
			"-token", "env://E2E_AUTH_TOKEN",
			"-target-id", targetId,
			"-keyring-type", "none",
			"-exec", "ls", // Execute something so that the command exits
			// Note: Would have used `connect ssh` here, but ssh does not exist in the image. Also,
			// this method only cares about creating a session entry in the database, so the ssh is unnecessary
		},
		Env: []string{
			"BOUNDARY_ADDR=" + boundaryAddr,
			"E2E_AUTH_TOKEN=" + token,
			"SKIP_CHOWN=true",
		},
		Name:     "boundary-client",
		Networks: []*dockertest.Network{network},
		CapAdd:   []string{"IPC_LOCK"},
	})
	require.NoError(t, err)

	return &Container{Resource: resource}
}

// StartOpenSshServer starts an openssh container to serve as a target for Boundary.
// Returns information about the container.
func StartOpenSshServer(t testing.TB, pool *dockertest.Pool, network *dockertest.Network, repository, tag, user, privateKeyFilePath string) *Container {
	t.Log("Starting openssh-server to serve as target...")
	c, err := LoadConfig()
	require.NoError(t, err)

	err = pool.Client.PullImage(docker.PullImageOptions{
		Repository: fmt.Sprintf("%s/%s", c.DockerMirror, repository),
		Tag:        tag,
	}, docker.AuthConfiguration{})
	require.NoError(t, err)

	privateKeyRaw, err := os.ReadFile(privateKeyFilePath)
	require.NoError(t, err)
	signer, err := ssh.ParsePrivateKey(privateKeyRaw)
	require.NoError(t, err)

	networkAlias := "target"
	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: fmt.Sprintf("%s/%s", c.DockerMirror, repository),
		Tag:        tag,
		Env: []string{
			"PUID=1000",
			"PGID=1000",
			"TZ=US/Eastern",
			"USER_NAME=" + user,
			"PUBLIC_KEY=" + string(ssh.MarshalAuthorizedKey(signer.PublicKey())),
		},
		Name:     networkAlias,
		Networks: []*dockertest.Network{network},
	})
	require.NoError(t, err)

	return &Container{
		Resource:   resource,
		UriNetwork: networkAlias,
	}
}

// StartMysql starts a MySQL database in a docker container.
// Returns information about the container
func StartMysql(t testing.TB, pool *dockertest.Pool, network *dockertest.Network, repository, tag string) *Container {
	t.Log("Starting MySQL database...")
	c, err := LoadConfig()
	require.NoError(t, err)

	err = pool.Client.PullImage(docker.PullImageOptions{
		Repository: fmt.Sprintf("%s/%s", c.DockerMirror, repository),
		Tag:        tag,
	}, docker.AuthConfiguration{})
	require.NoError(t, err)

	networkAlias := "e2emysql"
	mysqlDb := "e2eboundarydb"
	mysqlUser := "e2eboundary"
	mysqlPassword := "e2eboundary"
	mysqlRootPassword := "rootpassword"

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: fmt.Sprintf("%s/%s", c.DockerMirror, repository),
		Tag:        tag,
		Env: []string{
			"MYSQL_DATABASE=" + mysqlDb,
			"MYSQL_USER=" + mysqlUser,
			"MYSQL_PASSWORD=" + mysqlPassword,
			"MYSQL_ROOT_PASSWORD=" + mysqlRootPassword,
		},
		ExposedPorts: []string{"3306/tcp"},
		Name:         networkAlias,
		Networks:     []*dockertest.Network{network},
	})
	require.NoError(t, err)

	return &Container{
		Resource:     resource,
		UriLocalhost: fmt.Sprintf("mysql://%s:%s@localhost:3306/%s", mysqlUser, mysqlPassword, mysqlDb),
		UriNetwork:   fmt.Sprintf("mysql://%s:%s@%s:3306/%s", mysqlUser, mysqlPassword, networkAlias, mysqlDb),
	}
}

// StartCassandra starts a Cassandra database in a docker container.
// Returns information about the container
func StartCassandra(t testing.TB, pool *dockertest.Pool, network *dockertest.Network, repository, tag string) *Container {
	t.Log("Starting Cassandra database...")
	c, err := LoadConfig()
	require.NoError(t, err)

	err = pool.Client.PullImage(docker.PullImageOptions{
		Repository: fmt.Sprintf("%s/%s", c.DockerMirror, repository),
		Tag:        tag,
	}, docker.AuthConfiguration{})
	require.NoError(t, err)

	config := cassandraConfig{
		User:         "e2eboundary",
		Password:     "e2eboundary",
		Keyspace:     "e2eboundarykeyspace",
		NetworkAlias: "e2ecassandra",
	}

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: fmt.Sprintf("%s/%s", c.DockerMirror, repository),
		Tag:        tag,
		Env: []string{
			"CASSANDRA_CLUSTER_NAME=e2e-boundary-cluster",
		},

		ExposedPorts: []string{"9042/tcp"},
		Name:         config.NetworkAlias,
		Networks:     []*dockertest.Network{network},
	})
	require.NoError(t, err)

	// Cassandra container takes a while to start due to the gossip protocol needing to settle and establish connections.
	// This relies on the pool's extended maxWait time to ensure the container is healthy.
	err = pool.Retry(func() error {
		cmd := exec.Command("docker", "exec", config.NetworkAlias, "cqlsh", "-e", "SELECT now() FROM system.local;")
		output, cmdErr := cmd.CombinedOutput()
		if cmdErr != nil {
			return fmt.Errorf("failed to connect to Cassandra container '%s': %v\nOutput: %s", config.NetworkAlias, cmdErr, string(output))
		}
		return nil
	})
	require.NoError(t, err, "Cassandra container did not start in time or is not healthy")

	err = setupCassandraAuthAndUser(t, resource, pool, &config)
	require.NoError(t, err)

	return &Container{
		Resource: resource,
		UriLocalhost: fmt.Sprintf(
			"cassandra://%s:%s@%s/%s",
			config.User,
			config.Password,
			resource.GetHostPort("9042/tcp"),
			config.Keyspace,
		),
		UriNetwork: fmt.Sprintf(
			"cassandra://%s:%s@%s:9042/%s",
			config.User,
			config.Password,
			config.NetworkAlias,
			config.Keyspace,
		),
	}
}

// setupCassandraAuthAndUser enables authentication on a Cassandra container and creates a user with permissions.
func setupCassandraAuthAndUser(t testing.TB, resource *dockertest.Resource, pool *dockertest.Pool, config *cassandraConfig) error {
	t.Helper()
	t.Log("Configuring Cassandra authentication and user permissions...")

	t.Logf("Initializing Cassandra keyspace: %s...", config.Keyspace)
	createKeyspaceCmd := fmt.Sprintf(
		"CREATE KEYSPACE IF NOT EXISTS %s WITH replication = {'class': 'SimpleStrategy', 'replication_factor': 1};",
		config.Keyspace,
	)
	if err := exec.Command("docker", "exec", config.NetworkAlias, "cqlsh", "-e", createKeyspaceCmd).Run(); err != nil {
		return err
	}

	// Commands to enable authentication and authorization by editing cassandra.yaml
	sedCmd := []string{
		"sed", "-i",
		"-e", "s/^authenticator:.*/authenticator: PasswordAuthenticator/",
		"-e", "s/^authorizer:.*/authorizer: CassandraAuthorizer/",
		"-e", "s/^role_manager:.*/role_manager: CassandraRoleManager/",
		"/etc/cassandra/cassandra.yaml",
	}
	if _, err := resource.Exec(sedCmd, dockertest.ExecOptions{}); err != nil {
		return err
	}

	if err := pool.Client.RestartContainer(resource.Container.ID, uint(pool.MaxWait.Seconds())); err != nil {
		return err
	}
	t.Log("Waiting for Cassandra container to restart and apply authentication settings...")

	// Wait for Cassandra to be up with authentication enabled
	if err := pool.Retry(func() error {
		return exec.Command(
			"docker", "exec", config.NetworkAlias,
			"cqlsh", "-u", "cassandra", "-p", "cassandra",
			"-e", "SELECT now() FROM system.local;",
		).Run()
	}); err != nil {
		return err
	}

	t.Log("Creating Cassandra user and granting permissions...")
	cqlCmds := []string{
		fmt.Sprintf("CREATE ROLE IF NOT EXISTS %s WITH PASSWORD = '%s' AND LOGIN = true;", config.User, config.Password),
		fmt.Sprintf("GRANT ALL PERMISSIONS ON KEYSPACE %s TO %s;", config.Keyspace, config.User),
		fmt.Sprintf("USE %s; CREATE TABLE IF NOT EXISTS users (id UUID PRIMARY KEY, name TEXT, created_at TIMESTAMP);", config.Keyspace),
	}
	for _, cmd := range cqlCmds {
		if err := exec.Command(
			"docker", "exec", config.NetworkAlias,
			"cqlsh", "-u", "cassandra", "-p", "cassandra", "-e", cmd,
		).Run(); err != nil {
			return err
		}
	}
	return nil
}
