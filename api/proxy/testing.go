// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

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
func TestClientTlsConfig(t *testing.T, authzToken string, opt ...Option) *tls.Config {
	proxyClient, err := New(context.Background(), authzToken, opt...)
	require.NoError(t, err)
	tlsConf, err := proxyClient.clientTlsConfig(opt...)
	require.NoError(t, err)
	return tlsConf
}
