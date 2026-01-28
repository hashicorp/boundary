// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package util

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_JoinHostPort(t *testing.T) {
	t.Parallel()

	// The wrapper function is used to ensure that the
	// host input value is not already enclosed with
	// square brackets for ipv6 addresses. This is because
	// the underlying JoinHostPort() method will enclose the
	// existing square brackets with another pair of square
	// brackets.
	t.Run("ensure-net.JoinHostPort()-behavior", func(t *testing.T) {
		assert := assert.New(t)
		hostport := net.JoinHostPort("[2001:4860:4860:0:0:0:0:8888]", "80")
		assert.Equal("[[2001:4860:4860:0:0:0:0:8888]]:80", hostport)
	})

	tests := []struct {
		name            string
		host            string
		port            string
		expectedAddress string
	}{
		{
			name:            "local-ipv4",
			host:            "127.0.0.1",
			port:            "80",
			expectedAddress: "127.0.0.1:80",
		},
		{
			name:            "ipv4",
			host:            "8.8.8.8",
			port:            "80",
			expectedAddress: "8.8.8.8:80",
		},
		{
			name:            "ipv4-empty-port",
			host:            "8.8.8.8",
			expectedAddress: "8.8.8.8:",
		},
		{
			name:            "ipv4-square-brackets",
			host:            "[8.8.8.8]",
			port:            "80",
			expectedAddress: "8.8.8.8:80",
		},
		{
			name:            "missing-left-square-bracket",
			host:            "::1]",
			port:            "80",
			expectedAddress: "[::1]:80",
		},
		{
			name:            "missing-right-square-bracket",
			host:            "[::1",
			port:            "80",
			expectedAddress: "[::1]:80",
		},
		{
			name:            "local-no-square-brackets",
			host:            "::1",
			port:            "80",
			expectedAddress: "[::1]:80",
		},
		{
			name:            "local-no-square-brackets-missing-port",
			host:            "::1",
			expectedAddress: "[::1]:",
		},
		{
			name:            "ipv6-no-square-brackets",
			host:            "2001:4860:4860:0:0:0:0:8888",
			port:            "80",
			expectedAddress: "[2001:4860:4860:0:0:0:0:8888]:80",
		},
		{
			name:            "ipv6-no-square-brackets-missing-port",
			host:            "2001:4860:4860:0:0:0:0:8888",
			expectedAddress: "[2001:4860:4860:0:0:0:0:8888]:",
		},
		{
			name:            "abbreviated-ipv6-no-square-brackets",
			host:            "2001:4860:4860::8888",
			port:            "80",
			expectedAddress: "[2001:4860:4860::8888]:80",
		},
		{
			name:            "abbreviated-ipv6-no-square-brackets-missing-port",
			host:            "2001:4860:4860::8888",
			expectedAddress: "[2001:4860:4860::8888]:",
		},
		{
			name:            "local-square-brackets",
			host:            "[::1]",
			port:            "80",
			expectedAddress: "[::1]:80",
		},
		{
			name:            "local-double-square-brackets",
			host:            "[[::1]]",
			port:            "80",
			expectedAddress: "[::1]:80",
		},
		{
			name:            "local-square-brackets-missing-port",
			host:            "[::1]",
			expectedAddress: "[::1]:",
		},
		{
			name:            "local-double-square-brackets-missing-port",
			host:            "[[::1]]",
			expectedAddress: "[::1]:",
		},
		{
			name:            "ipv6-square-brackets",
			host:            "[2001:4860:4860:0:0:0:0:8888]",
			port:            "80",
			expectedAddress: "[2001:4860:4860:0:0:0:0:8888]:80",
		},
		{
			name:            "ipv6-dobule-square-brackets",
			host:            "[[2001:4860:4860:0:0:0:0:8888]]",
			port:            "80",
			expectedAddress: "[2001:4860:4860:0:0:0:0:8888]:80",
		},
		{
			name:            "ipv6-square-brackets-missing-port",
			host:            "[2001:4860:4860:0:0:0:0:8888]",
			expectedAddress: "[2001:4860:4860:0:0:0:0:8888]:",
		},
		{
			name:            "ipv6-double-square-brackets-missing-port",
			host:            "[[2001:4860:4860:0:0:0:0:8888]]",
			expectedAddress: "[2001:4860:4860:0:0:0:0:8888]:",
		},
		{
			name:            "abbreviated-ipv6-square-brackets",
			host:            "[2001:4860:4860::8888]",
			port:            "80",
			expectedAddress: "[2001:4860:4860::8888]:80",
		},
		{
			name:            "abbreviated-ipv6-double-square-brackets",
			host:            "[[2001:4860:4860::8888]]",
			port:            "80",
			expectedAddress: "[2001:4860:4860::8888]:80",
		},
		{
			name:            "abbreviated-ipv6-square-brackets-missing-port",
			host:            "[2001:4860:4860::8888]",
			expectedAddress: "[2001:4860:4860::8888]:",
		},
		{
			name:            "abbreviated-ipv6-double-square-brackets-missing-port",
			host:            "[[2001:4860:4860::8888]]",
			expectedAddress: "[2001:4860:4860::8888]:",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			actualAddress := JoinHostPort(tt.host, tt.port)
			assert.Equal(tt.expectedAddress, actualAddress)
		})
	}
}

func Test_SplitHostPort(t *testing.T) {
	t.Parallel()

	// The wrapper function is used to ignore missing port error.
	// We need to validate the behavior of the underlying
	// SplitHostPort() method hasn't changed.
	t.Run("ensure-net.SplitHostPort()-behavior", func(t *testing.T) {
		require, assert := require.New(t), assert.New(t)
		host, port, err := net.SplitHostPort("[2001:4860:4860:0:0:0:0:8888]")
		require.Error(err)
		assert.ErrorContains(err, "missing port in address")
		assert.Empty(host)
		assert.Empty(port)
	})

	tests := []struct {
		name         string
		hostport     string
		expectedHost string
		expectedPort string
		expectedErr  error
	}{
		{
			name:         "local-ipv4",
			hostport:     "127.0.0.1:80",
			expectedHost: "127.0.0.1",
			expectedPort: "80",
		},
		{
			name:         "ipv4",
			hostport:     "8.8.8.8:80",
			expectedHost: "8.8.8.8",
			expectedPort: "80",
		},
		{
			name:         "ipv4-missing-port",
			hostport:     "8.8.8.8",
			expectedHost: "8.8.8.8",
			expectedErr:  ErrMissingPort,
		},
		{
			name:         "ipv4-empty-port",
			hostport:     "8.8.8.8:",
			expectedHost: "8.8.8.8",
		},
		{
			name:         "ipv4-square-brackets",
			hostport:     "[8.8.8.8]:80",
			expectedHost: "8.8.8.8",
			expectedPort: "80",
		},
		{
			name:         "ipv6-square-brackets",
			hostport:     "::1:80",
			expectedHost: "::1:80",
			expectedErr:  ErrMissingPort,
		},
		{
			name:         "ipv6-missing-port",
			hostport:     "[::1]",
			expectedHost: "::1",
			expectedErr:  ErrMissingPort,
		},
		{
			name:         "ipv6-empty-port",
			hostport:     "[::1]:",
			expectedHost: "::1",
		},
		{
			name:         "local-ipv6",
			hostport:     "[::1]:80",
			expectedHost: "::1",
			expectedPort: "80",
		},
		{
			name:         "ipv6",
			hostport:     "[2001:4860:4860:0:0:0:0:8888]:80",
			expectedHost: "2001:4860:4860:0:0:0:0:8888",
			expectedPort: "80",
		},
		{
			name:         "abbreviated-ipv6",
			hostport:     "[2001:4860:4860::8888]:80",
			expectedHost: "2001:4860:4860::8888",
			expectedPort: "80",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			actualHost, actualPort, err := SplitHostPort(tt.hostport)
			if tt.expectedErr != nil {
				require.ErrorIs(t, err, tt.expectedErr)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tt.expectedHost, actualHost)
			require.Equal(t, tt.expectedPort, actualPort)
		})
	}
}

func Test_ParseAddress(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		address         string
		expectedAddress string
		expectedErrMsg  string
	}{
		{
			name:           "empty-address",
			expectedErrMsg: "invalid address length",
		},
		{
			name:           "empty-spaces",
			address:        "          ",
			expectedErrMsg: "invalid address length",
		},
		{
			name:           "invalid-short-address",
			address:        "ab",
			expectedErrMsg: "invalid address length",
		},
		{
			name:           "invalid-long-address",
			address:        strings.Repeat("a", 256),
			expectedErrMsg: "invalid address length",
		},
		{
			name:            "valid-dns-name",
			address:         "www.google.com",
			expectedAddress: "www.google.com",
		},
		{
			name:            "valid-dns-name-trim-empty-spaces",
			address:         "  www.google.com    ",
			expectedAddress: "www.google.com",
		},
		{
			name:            "valid-ipv4",
			address:         "127.0.0.1",
			expectedAddress: "127.0.0.1",
		},
		{
			name:           "invalid-ipv4-with-port",
			address:        "127.0.0.1:80",
			expectedErrMsg: "address contains a port",
		},
		{
			name:            "valid-ipv6",
			address:         "2001:4860:4860:0:0:0:0:8888",
			expectedAddress: "2001:4860:4860::8888",
		},
		{
			name:           "valid-[ipv6]",
			address:        "[2001:4860:4860:0:0:0:0:8888]",
			expectedErrMsg: "address cannot be encapsulated by brackets",
		},
		{
			name:           "valid-[ipv6]:",
			address:        "[2001:4860:4860:0:0:0:0:8888]:",
			expectedErrMsg: "url has malformed host: missing port value after colon",
		},
		{
			name:           "invalid-ipv6-with-port",
			address:        "[2001:4860:4860:0:0:0:0:8888]:80",
			expectedErrMsg: "address contains a port",
		},
		{
			name:            "valid-abbreviated-ipv6",
			address:         "2001:4860:4860::8888",
			expectedAddress: "2001:4860:4860::8888",
		},
		{
			name:           "valid-abbreviated-[ipv6]",
			address:        "[2001:4860:4860::8888]",
			expectedErrMsg: "address cannot be encapsulated by brackets",
		},
		{
			name:           "valid-abbreviated-[ipv6]:",
			address:        "[2001:4860:4860::8888]:",
			expectedErrMsg: "url has malformed host: missing port value after colon",
		},
		{
			name:           "invalid-abbreviated-[ipv6]-with-port",
			address:        "[2001:4860:4860::8888]:80",
			expectedErrMsg: "address contains a port",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)
			actualAddress, err := ParseAddress(context.Background(), tt.address)
			if tt.expectedErrMsg != "" {
				require.Error(err)
				assert.ErrorContains(err, tt.expectedErrMsg)
				return
			}
			require.NoError(err)
			assert.Equal(tt.expectedAddress, actualAddress)
		})
	}
}
