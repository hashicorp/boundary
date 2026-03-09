// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"testing"

	"github.com/hashicorp/boundary/internal/credential/vault"
)

// TestVaultServer is a vault server running in a docker container suitable
// for testing.
type TestVaultServer struct {
	*vault.TestVaultServer
}

// NewTestVaultServer creates and returns a TestVaultServer. Some Vault
// secret engines require the Vault server be created with a docker
// network. Check the Mount method for the Vault secret engine to see if a
// docker network is required.
//
// WithTestVaultTLS and WithDockerNetwork are the only valid options.
// Setting the WithDockerNetwork option can significantly increase the
// amount of time required for a test to run.
func NewTestVaultServer(t *testing.T, opt ...TestOption) *TestVaultServer {
	t.Helper()

	opts := getTestOpts(t, opt...)
	var internalOpts []vault.TestOption
	switch opts.vaultTLS {
	case TestNoTLS:
		internalOpts = append(internalOpts, vault.WithTestVaultTLS(vault.TestNoTLS))
	case TestServerTLS:
		internalOpts = append(internalOpts, vault.WithTestVaultTLS(vault.TestServerTLS))
	case TestClientTLS:
		internalOpts = append(internalOpts, vault.WithTestVaultTLS(vault.TestClientTLS))
	}
	internalOpts = append(internalOpts, vault.WithDockerNetwork(opts.dockerNetwork))

	ts := vault.NewTestVaultServer(t, internalOpts...)
	return &TestVaultServer{ts}
}

// TestVaultTLS represents the TLS configuration level of a
// TestVaultServer.
type TestVaultTLS int

const (
	// TestNoTLS disables TLS. The test server Addr begins with http://.
	TestNoTLS TestVaultTLS = iota // no TLS

	// TestServerTLS configures the Vault test server listener to use TLS.
	// A CA certificate is generated and a server certificate is issued
	// from the CA certificate. The CA certificate is available in the
	// CaCert field of the TestVaultServer. The test server Addr begins
	// with https://.
	TestServerTLS

	// TestClientTLS configures the Vault test server listener to require a
	// client certificate for mTLS and includes all of the settings from
	// TestServerTLS. A second CA certificate is generated and a client
	// certificate is issued from this CA certificate. The client
	// certificate and the client certificate key are available in the in
	// the ClientCert and ClientKey fields of the TestVaultServer
	// respectively.
	TestClientTLS
)

// TestOption - how Options are passed as arguments.
type TestOption func(*testing.T, *testOptions)

// options = how options are represented
type testOptions struct {
	vaultTLS      TestVaultTLS
	dockerNetwork bool
}

func getTestOpts(t *testing.T, opt ...TestOption) testOptions {
	t.Helper()
	opts := getDefaultTestOptions(t)
	for _, o := range opt {
		o(t, &opts)
	}
	return opts
}

func getDefaultTestOptions(t *testing.T) testOptions {
	t.Helper()
	return testOptions{
		vaultTLS:      TestNoTLS,
		dockerNetwork: false,
	}
}

// WithTestVaultTLS sets the Vault TLS option.
// TestNoTLS is the default TLS option.
func WithTestVaultTLS(s TestVaultTLS) TestOption {
	return func(t *testing.T, o *testOptions) {
		t.Helper()
		o.vaultTLS = s
	}
}

// WithDockerNetwork sets the option to create docker network when creating
// a Vault test server. The default is to not create a docker network.
func WithDockerNetwork(b bool) TestOption {
	return func(t *testing.T, o *testOptions) {
		t.Helper()
		o.dockerNetwork = b
	}
}
