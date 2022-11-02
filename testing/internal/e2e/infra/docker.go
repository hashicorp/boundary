package infra

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"testing"

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

	networkAlias := "e2epostgres"
	postgresDb := "e2eboundarydb"
	postgresUser := "e2eboundary"
	postgresPassword := "e2eboundary"
	postgresConfigFilePath, err := filepath.Abs("testdata/postgresql.conf")
	require.NoError(t, err)

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "postgres",
		Tag:        "13-alpine",
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

	boundaryConfigFilePath, err := filepath.Abs("testdata/boundary-config.hcl")
	require.NoError(t, err)

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "hashicorp/boundary",
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

// StartBoundary starts a boundary container and spins up an instance of boundary using the
// specified database at postgresURI. Returns information about the container.
// Returns information about the container
func StartBoundary(t testing.TB, pool *dockertest.Pool, network *dockertest.Network, postgresURI string) *Container {
	t.Log("Starting Boundary...")

	boundaryConfigFilePath, err := filepath.Abs("testdata/boundary-config.hcl")
	require.NoError(t, err)

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "hashicorp/boundary",
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

// ConnectToTarget starts a boundary container and attempts to connect to the specified target.
// Returns information about the container.
func ConnectToTarget(t testing.TB, pool *dockertest.Pool, network *dockertest.Network, boundaryAddr string, token string, targetId string) *Container {
	t.Log("Connecting to target...")

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "hashicorp/boundary",
		Tag:        "latest",
		Cmd: []string{
			"boundary", "connect",
			"-token", "env://E2E_AUTH_TOKEN",
			"-target-id", targetId,
			"-exec", "ls", // Needed to execute something so that the command exits
			// Note: Would have used `connect ssh` here, but ssh does not exist in the image
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

	privateKeyRaw, err := os.ReadFile(privateKeyFilePath)
	require.NoError(t, err)
	signer, err := ssh.ParsePrivateKey(privateKeyRaw)
	require.NoError(t, err)

	networkAlias := "target"
	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "lscr.io/linuxserver/openssh-server",
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
