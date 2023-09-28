package proxy

import (
	"context"
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestClientTlsConfig is designed to allow tests to obtain the TLS
// configuration that would be used by the proxy in order to make specific calls
// to workers during tests.
func TestClientTlsConfig(t *testing.T, authzToken string) *tls.Config {
	proxyClient, err := New(context.Background(), authzToken)
	require.NoError(t, err)
	tlsConf, err := proxyClient.clientTlsConfig()
	require.NoError(t, err)
	return tlsConf
}
