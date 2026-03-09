// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"crypto/tls"
	"math"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigSetAddress(t *testing.T) {
	type test struct {
		name    string
		input   string
		address string
		err     string
	}

	tests := []test{
		{
			"ipv4",
			"http://127.0.0.1:9200",
			"http://127.0.0.1:9200",
			"",
		},
		{
			"ipv6",
			"http://[::1]:9200",
			"http://[::1]:9200",
			"",
		},
		{
			"bare with version",
			"http://127.0.0.1:9200/v1",
			"http://127.0.0.1:9200",
			"",
		},
		{
			"bare with version and trailing slash",
			"http://127.0.0.1:9200/v1/",
			"http://127.0.0.1:9200",
			"",
		},
		{
			"valid top level scope",
			"http://127.0.0.1:9200/v1/scopes",
			"http://127.0.0.1:9200",
			"",
		},
		{
			"valid scope",
			"http://127.0.0.1:9200/v1/scopes/scopeid",
			"http://127.0.0.1:9200",
			"",
		},
		{
			"longer path project",
			"http://127.0.0.1:9200/v1/auth-methods",
			"http://127.0.0.1:9200",
			"",
		},
		{
			"valid project",
			"http://127.0.0.1:9200/my-install",
			"http://127.0.0.1:9200/my-install",
			"",
		},
		{
			"valid project path containing v1",
			"http://127.0.0.1:9200/randomPathHasv1InIt",
			"http://127.0.0.1:9200/randomPathHasv1InIt",
			"",
		},
	}

	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			var c Config
			err := c.setAddr(v.input)
			if err != nil {
				assert.Equal(t, v.err, err.Error())
			}
			assert.Equal(t, v.address, c.Addr)
		})
	}
}

func TestReadEnvironmentMaxRetries(t *testing.T) {
	tests := []struct {
		name           string
		inp            string
		expMaxRetries  int
		expErrContains string
	}{
		{
			name:           "invalidNaN",
			inp:            "bad",
			expErrContains: "strconv.ParseUint: parsing \"bad\": invalid syntax",
		},
		{
			name:           "invalidNegativeNumber",
			inp:            "-1",
			expErrContains: "strconv.ParseUint: parsing \"-1\": invalid syntax",
		},
		{
			name:           "invalidGreaterThanUint32",
			inp:            strconv.Itoa(math.MaxUint32 + 10),
			expErrContains: "strconv.ParseUint: parsing \"4294967305\": value out of range",
		},
		{
			name:           "invalidGreaterThanInt32",
			inp:            strconv.Itoa(math.MaxInt32 + 10),
			expErrContains: "max retries must be less than or equal to 2147483647",
		},
		{
			name:          "success1",
			inp:           "0",
			expMaxRetries: 0,
		},
		{
			name:          "success2",
			inp:           "10000",
			expMaxRetries: 10000,
		},
		{
			name:          "successMaxInt32",
			inp:           strconv.Itoa(math.MaxInt32),
			expMaxRetries: math.MaxInt32,
		},
		{
			name:          "successNothing",
			inp:           "",
			expMaxRetries: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv(EnvBoundaryMaxRetries, tt.inp)
			t.Cleanup(func() { os.Unsetenv(EnvBoundaryMaxRetries) })

			var c Config
			err := c.ReadEnvironment()
			if tt.expErrContains != "" {
				require.ErrorContains(t, err, tt.expErrContains)
				require.Equal(t, 0, c.MaxRetries)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.expMaxRetries, c.MaxRetries)
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	tests := []struct {
		name    string
		envvars map[string]string
		want    *Config
	}{
		{
			name:    "noEnvVarsSet",
			envvars: nil,
			want: &Config{
				Addr:               "http://127.0.0.1:9200",
				Token:              "",
				RecoveryKmsWrapper: nil,
				HttpClient: func() *http.Client {
					client := cleanhttp.DefaultPooledClient()
					client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{
						MinVersion: tls.VersionTLS12,
					}
					return client
				}(),
				TLSConfig:        &TLSConfig{},
				Headers:          map[string][]string{},
				MaxRetries:       2,
				Timeout:          time.Second * 60,
				Backoff:          RateLimitLinearJitterBackoff,
				CheckRetry:       nil,
				Limiter:          nil,
				OutputCurlString: false,
				SRVLookup:        false,
			},
		},
		{
			name: "maxRetries",
			envvars: map[string]string{
				"BOUNDARY_MAX_RETRIES": "5",
			},
			want: &Config{
				Addr:               "http://127.0.0.1:9200",
				Token:              "",
				RecoveryKmsWrapper: nil,
				HttpClient: func() *http.Client {
					client := cleanhttp.DefaultPooledClient()
					client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{
						MinVersion: tls.VersionTLS12,
					}
					return client
				}(),
				TLSConfig:        &TLSConfig{},
				Headers:          map[string][]string{},
				MaxRetries:       5,
				Timeout:          time.Second * 60,
				Backoff:          RateLimitLinearJitterBackoff,
				CheckRetry:       nil,
				Limiter:          nil,
				OutputCurlString: false,
				SRVLookup:        false,
			},
		},
	}
	for _, tt := range tests {
		for k, v := range tt.envvars {
			os.Setenv(k, v)
		}
		t.Cleanup(func() {
			for k := range tt.envvars {
				os.Unsetenv(k)
			}
		})

		c, err := DefaultConfig()
		require.NoError(t, err)

		assert.Empty(t,
			cmp.Diff(tt.want, c,
				cmpopts.IgnoreUnexported(http.Transport{}, tls.Config{}),
				// Ignore fields that are functions, since cmp.Diff can't
				// correctly compare them if they are non-nil.
				cmpopts.IgnoreFields(Config{}, "Backoff"),
				cmpopts.IgnoreFields(http.Transport{}, "Proxy", "DialContext"),
			))
	}
}
