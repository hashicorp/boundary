// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package infra

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
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

// StartBoundaryDatabase spins up a postgres database in a docker container.
// Returns information about the container
func StartBoundaryDatabase(t testing.TB, pool *dockertest.Pool, network *dockertest.Network) *Container {
	t.Log("Starting postgres database...")
	c, err := LoadConfig()
	require.NoError(t, err)

	networkAlias := "e2epostgres"
	postgresDb := "e2eboundarydb"
	postgresUser := "e2eboundary"
	postgresPassword := "e2eboundary"
	postgresConfigFilePath, err := filepath.Abs("testdata/postgresql.conf")
	require.NoError(t, err)

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: c.DockerMirror + "/library/postgres",
		Tag:        "latest",
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
func InitBoundaryDatabase(t testing.TB, pool *dockertest.Pool, network *dockertest.Network, postgresURI string) *Container {
	t.Log("Initializing postgres database...")
	c, err := LoadConfig()
	require.NoError(t, err)

	boundaryConfigFilePath, err := filepath.Abs("testdata/boundary-config.hcl")
	require.NoError(t, err)

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: c.DockerMirror + "/hashicorp/boundary",
		Tag:        "latest",
		Cmd:        []string{"boundary", "database", "init", "-config", "/boundary/boundary-config.hcl", "-format", "json"},
		Env: []string{
			"BOUNDARY_POSTGRES_URL=" + postgresURI,
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
func StartBoundary(t testing.TB, pool *dockertest.Pool, network *dockertest.Network, postgresURI string) *Container {
	t.Log("Starting Boundary...")
	c, err := LoadConfig()
	require.NoError(t, err)

	boundaryConfigFilePath, err := filepath.Abs("testdata/boundary-config.hcl")
	require.NoError(t, err)

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: c.DockerMirror + "/hashicorp/boundary",
		Tag:        "latest",
		Cmd:        []string{"boundary", "server", "-config", "/boundary/boundary-config.hcl"},
		Env: []string{
			"BOUNDARY_POSTGRES_URL=" + postgresURI,
			"HOSTNAME=boundary",
			"SKIP_CHOWN=true",
		},
		Mounts:       []string{path.Dir(boundaryConfigFilePath) + ":/boundary/"},
		Name:         "boundary",
		Networks:     []*dockertest.Network{network},
		ExposedPorts: []string{"9200", "9201", "9202", "9203"},
		PortBindings: map[docker.Port][]docker.PortBinding{
			"9200/tcp": {{HostIP: "localhost", HostPort: "9200/tcp"}},
			"9201/tcp": {{HostIP: "localhost", HostPort: "9201/tcp"}},
			"9202/tcp": {{HostIP: "localhost", HostPort: "9202/tcp"}},
			"9203/tcp": {{HostIP: "localhost", HostPort: "9203/tcp"}},
		},
		CapAdd: []string{"IPC_LOCK"},
	})
	require.NoError(t, err)

	return &Container{
		Resource:     resource,
		UriLocalhost: "http://localhost:9200",
		UriNetwork:   "http://boundary:9200",
	}
}

// StartVault starts a vault container.
// Returns information about the container.
func StartVault(t testing.TB, pool *dockertest.Pool, network *dockertest.Network) (*Container, string) {
	t.Log("Starting Vault...")
	c, err := LoadConfig()
	require.NoError(t, err)

	vaultToken := "boundarytok"
	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: c.DockerMirror + "/hashicorp/vault",
		Tag:        "latest",
		Env: []string{
			"VAULT_DEV_ROOT_TOKEN_ID=" + vaultToken,
		},
		Name:         "vault",
		Networks:     []*dockertest.Network{network},
		ExposedPorts: []string{"8200"},
		PortBindings: map[docker.Port][]docker.PortBinding{
			"8200/tcp": {{HostIP: "localhost", HostPort: "8210/tcp"}},
		},
		CapAdd: []string{"IPC_LOCK"},
	})
	require.NoError(t, err)

	uriLocalhost := "http://localhost:8210"

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
func ConnectToTarget(t testing.TB, pool *dockertest.Pool, network *dockertest.Network, boundaryAddr string, token string, targetId string) *Container {
	t.Log("Connecting to target...")
	c, err := LoadConfig()
	require.NoError(t, err)

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: c.DockerMirror + "/hashicorp/boundary",
		Tag:        "latest",
		Cmd: []string{
			"boundary", "connect",
			"-token", "env://E2E_AUTH_TOKEN",
			"-target-id", targetId,
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
func StartOpenSshServer(t testing.TB, pool *dockertest.Pool, network *dockertest.Network, user string, privateKeyFilePath string) *Container {
	t.Log("Starting openssh-server to serve as target...")
	c, err := LoadConfig()
	require.NoError(t, err)

	privateKeyRaw, err := os.ReadFile(privateKeyFilePath)
	require.NoError(t, err)
	signer, err := ssh.ParsePrivateKey(privateKeyRaw)
	require.NoError(t, err)

	networkAlias := "target"
	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: c.DockerMirror + "/linuxserver/openssh-server",
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
