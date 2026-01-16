// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/boundary/internal/ratelimit"
	"github.com/hashicorp/boundary/internal/util"
	configutil "github.com/hashicorp/go-secure-stdlib/configutil/v2"
	"github.com/hashicorp/go-secure-stdlib/listenerutil"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDevController(t *testing.T) {
	actual, err := DevController()
	if err != nil {
		t.Fatal(err)
	}

	truePointer := new(bool)
	*truePointer = true

	apiHeaders := map[int]http.Header{
		0: {
			"Content-Security-Policy":   {"default-src 'none'"},
			"X-Content-Type-Options":    {"nosniff"},
			"Strict-Transport-Security": {"max-age=31536000; includeSubDomains"},
			"Cache-Control":             {"no-store"},
		},
	}
	uiHeaders := map[int]http.Header{
		0: {
			"Content-Security-Policy":   {defaultCsp},
			"X-Content-Type-Options":    {"nosniff"},
			"Strict-Transport-Security": {"max-age=31536000; includeSubDomains"},
			"Cache-Control":             {"no-store"},
		},
	}

	exp := &Config{
		Eventing: event.DefaultEventerConfig(),
		SharedConfig: &configutil.SharedConfig{
			DisableMlock: true,
			Listeners: []*listenerutil.ListenerConfig{
				{
					Type:                     "tcp",
					Purpose:                  []string{"api"},
					TLSDisable:               true,
					CorsEnabled:              truePointer,
					CorsAllowedOrigins:       []string{"*"},
					CustomApiResponseHeaders: apiHeaders,
					CustomUiResponseHeaders:  uiHeaders,
				},
				{
					Type:                     "tcp",
					Purpose:                  []string{"cluster"},
					CustomApiResponseHeaders: apiHeaders,
					CustomUiResponseHeaders:  uiHeaders,
				},
				{
					Type:                     "tcp",
					Purpose:                  []string{"ops"},
					TLSDisable:               true,
					CustomApiResponseHeaders: apiHeaders,
					CustomUiResponseHeaders:  uiHeaders,
				},
			},
			Seals: []*configutil.KMS{
				{
					Type:    "aead",
					Purpose: []string{"root"},
					Config: map[string]string{
						"aead_type": "aes-gcm",
						"key_id":    "global_root",
					},
				},
				{
					Type:    "aead",
					Purpose: []string{"worker-auth"},
					Config: map[string]string{
						"aead_type": "aes-gcm",
						"key_id":    "global_worker-auth",
					},
				},
				{
					Type:    "aead",
					Purpose: []string{"bsr"},
					Config: map[string]string{
						"aead_type": "aes-gcm",
						"key_id":    "global_bsr",
					},
				},
				{
					Type:    "aead",
					Purpose: []string{"recovery"},
					Config: map[string]string{
						"aead_type": "aes-gcm",
						"key_id":    "global_recovery",
					},
				},
			},
		},
		Controller: &Controller{
			Name:                    "dev-controller",
			Description:             "A default controller created in dev mode",
			ApiRateLimits:           make(ratelimit.Configs, 0),
			ApiRateLimiterMaxQuotas: ratelimit.DefaultLimiterMaxQuotas(),
		},
		DevController: true,
	}
	exp.Eventing.ErrorEventsDisabled = true
	exp.Eventing.SysEventsEnabled = false
	exp.Eventing.ObservationsEnabled = false

	exp.Listeners[0].RawConfig = actual.Listeners[0].RawConfig
	exp.Listeners[1].RawConfig = actual.Listeners[1].RawConfig
	exp.Listeners[2].RawConfig = actual.Listeners[2].RawConfig
	exp.Seals[0].Config["key"] = actual.Seals[0].Config["key"]
	exp.Seals[1].Config["key"] = actual.Seals[1].Config["key"]
	exp.Seals[2].Config["key"] = actual.Seals[2].Config["key"]
	exp.Seals[3].Config["key"] = actual.Seals[3].Config["key"]
	exp.DevControllerKey = actual.Seals[0].Config["key"]
	exp.DevWorkerAuthKey = actual.Seals[1].Config["key"]
	exp.DevBsrKey = actual.Seals[2].Config["key"]
	exp.DevRecoveryKey = actual.Seals[3].Config["key"]

	assert.Equal(t, exp, actual)

	// Do some CORS-specific testing
	{
		// CORS disabled
		conf := `
		listener "tcp" {
			purpose = "api"
			cors_enabled = false
		}
		`
		actual, err = Parse(conf)
		assert.NoError(t, err)
		l0 := actual.Listeners[0]
		assert.False(t, *l0.CorsEnabled)
		assert.Empty(t, l0.CorsAllowedHeaders)

		// Enabled with a wildcard
		conf = `
		listener "tcp" {
			purpose = "api"
			cors_enabled = true
			cors_allowed_origins = ["*"]
		}
		`
		actual, err = Parse(conf)
		assert.NoError(t, err)
		l0 = actual.Listeners[0]
		assert.True(t, *l0.CorsEnabled)
		assert.Equal(t, []string{"*"}, l0.CorsAllowedOrigins)
		assert.Nil(t, l0.CorsDisableDefaultAllowedOriginValues)

		// Disabled, default behavior
		conf = `
		listener "tcp" {
			purpose = "api"
		}
		`
		actual, err = Parse(conf)
		assert.NoError(t, err)
		l0 = actual.Listeners[0]
		assert.True(t, *l0.CorsEnabled)
		assert.Equal(t, []string{"*"}, l0.CorsAllowedOrigins)
		assert.Nil(t, l0.CorsDisableDefaultAllowedOriginValues)

		// Disabled, default behavior
		conf = `
		listener "tcp" {
			purpose = "api"
			cors_disable_default_allowed_origin_values = true
		}
		`
		actual, err = Parse(conf)
		assert.NoError(t, err)
		l0 = actual.Listeners[0]
		assert.Nil(t, l0.CorsEnabled)
		assert.Empty(t, l0.CorsAllowedOrigins)
		assert.True(t, *l0.CorsDisableDefaultAllowedOriginValues)
	}

	// Test plugins block
	{
		// CORS disabled
		conf := `
		plugins {
			execution_dir = "/tmp/foobar"
		}
		`
		actual, err = Parse(conf)
		assert.NoError(t, err)
		assert.Equal(t, actual.Plugins.ExecutionDir, "/tmp/foobar")
	}
}

func TestDevWorker(t *testing.T) {
	actual, err := DevWorker(WithSysEventsEnabled(true), WithObservationsEnabled(true), TestWithErrorEventsEnabled(t, true))
	if err != nil {
		t.Fatal(err)
	}
	exp := &Config{
		Eventing: event.DefaultEventerConfig(),
		SharedConfig: &configutil.SharedConfig{
			DisableMlock: true,
			Listeners: []*listenerutil.ListenerConfig{
				{
					Type:    "tcp",
					Purpose: []string{"proxy"},
					CustomApiResponseHeaders: map[int]http.Header{
						0: {
							"Content-Security-Policy":   {"default-src 'none'"},
							"X-Content-Type-Options":    {"nosniff"},
							"Strict-Transport-Security": {"max-age=31536000; includeSubDomains"},
							"Cache-Control":             {"no-store"},
						},
					},
					CustomUiResponseHeaders: map[int]http.Header{
						0: {
							"Content-Security-Policy":   {defaultCsp},
							"X-Content-Type-Options":    {"nosniff"},
							"Strict-Transport-Security": {"max-age=31536000; includeSubDomains"},
							"Cache-Control":             {"no-store"},
						},
					},
				},
			},
			Seals: []*configutil.KMS{
				{
					Type:    "aead",
					Purpose: []string{"worker-auth-storage"},
					Config: map[string]string{
						"aead_type": "aes-gcm",
						"key_id":    "worker-auth-storage",
					},
				},
			},
		},
		Worker: &Worker{
			Name:                "w_1234567890",
			Description:         "A default worker created in dev mode",
			InitialUpstreams:    []string{"127.0.0.1"},
			InitialUpstreamsRaw: []any{"127.0.0.1"},
			Tags: map[string][]string{
				"type": {"dev", "local"},
			},
		},
	}

	exp.Listeners[0].RawConfig = actual.Listeners[0].RawConfig
	exp.Seals[0].Config["key"] = actual.Seals[0].Config["key"]
	exp.Worker.TagsRaw = actual.Worker.TagsRaw
	assert.Equal(t, exp, actual)

	// Redo it with key=value syntax for tags
	devWorkerKeyValueConfig := `
	listener "tcp" {
		purpose = "proxy"
	}

	worker {
		name = "w_1234567890"
		description = "A default worker created in dev mode"
		initial_upstreams = ["127.0.0.1"]
		tags = ["type=dev", "type=local"]
	}
	`

	actual, err = Parse(devConfig + devWorkerKeyValueConfig)
	assert.NoError(t, err)
	exp.Listeners[0].RawConfig = actual.Listeners[0].RawConfig
	exp.Seals = nil
	exp.Worker.TagsRaw = actual.Worker.TagsRaw
	assert.Equal(t, exp, actual)

	// Handle when there is a singular value not indicated as a slice
	devWorkerKeyValueConfig = `
	listener "tcp" {
		purpose = "proxy"
	}

	worker {
		name = "w_1234567890"
		description = "A default worker created in dev mode"
		initial_upstreams = ["127.0.0.1"]
		tags {
			type = "local"
		}
	}
	`

	actual, err = Parse(devConfig + devWorkerKeyValueConfig)
	assert.NoError(t, err)
	exp.Listeners[0].RawConfig = actual.Listeners[0].RawConfig
	exp.Worker.TagsRaw = actual.Worker.TagsRaw
	prevTags := exp.Worker.Tags
	exp.Worker.Tags = map[string][]string{"type": {"local"}}
	assert.Equal(t, exp, actual)
	exp.Worker.Tags = prevTags

	// Redo it with non-lower-cased keys
	devWorkerKeyValueConfig = `
	listener "tcp" {
		purpose = "proxy"
	}

	worker {
		name = "w_1234567890"
		description = "A default worker created in dev mode"
		initial_upstreams = ["127.0.0.1"]
		tags = ["tyPe=dev", "type=local"]
	}
	`

	_, err = Parse(devConfig + devWorkerKeyValueConfig)
	assert.Error(t, err)

	// Redo it with non-lower-cased values
	devWorkerKeyValueConfig = `
		listener "tcp" {
			purpose = "proxy"
		}

		worker {
			name = "w_1234567890"
			description = "A default worker created in dev mode"
			initial_upstreams = ["127.0.0.1"]
			tags = ["type=dev", "type=loCal"]
		}
		`

	_, err = Parse(devConfig + devWorkerKeyValueConfig)
	assert.Error(t, err)

	// Redo with non-printable characters to validate the strutil function
	devWorkerKeyValueConfig = `
	listener "tcp" {
		purpose = "proxy"
	}

	worker {
		name = "dev-work\u0000er"
		description = "A default worker created in dev mode"
		initial_upstreams = ["127.0.0.1"]
		tags = ["type=dev", "type=local"]
	}
	`

	_, err = Parse(devConfig + devWorkerKeyValueConfig)
	assert.Error(t, err)

	// Check activation token parsing
	devWorkerActivationTokenConfig := `
		listener "tcp" {
			purpose = "proxy"
		}
	
		worker {
			name = "dev-worker"
			description = "A default worker created in dev mode"
			initial_upstreams = ["127.0.0.1"]
			controller_generated_activation_token = "foobar"
		}
		`

	actual, err = Parse(devConfig + devWorkerActivationTokenConfig)
	require.NoError(t, err)
	assert.Equal(t, "foobar", actual.Worker.ControllerGeneratedActivationToken)
}

func TestDevCombined(t *testing.T) {
	actual, err := DevCombined()
	if err != nil {
		t.Fatal(err)
	}

	truePointer := new(bool)
	*truePointer = true

	apiHeaders := map[int]http.Header{
		0: {
			"Content-Security-Policy":   {"default-src 'none'"},
			"X-Content-Type-Options":    {"nosniff"},
			"Strict-Transport-Security": {"max-age=31536000; includeSubDomains"},
			"Cache-Control":             {"no-store"},
		},
	}
	uiHeaders := map[int]http.Header{
		0: {
			"Content-Security-Policy":   {defaultCsp},
			"X-Content-Type-Options":    {"nosniff"},
			"Strict-Transport-Security": {"max-age=31536000; includeSubDomains"},
			"Cache-Control":             {"no-store"},
		},
	}

	exp := &Config{
		Eventing: event.DefaultEventerConfig(),
		SharedConfig: &configutil.SharedConfig{
			DisableMlock: true,
			Listeners: []*listenerutil.ListenerConfig{
				{
					Type:                     "tcp",
					Purpose:                  []string{"api"},
					TLSDisable:               true,
					CorsEnabled:              truePointer,
					CorsAllowedOrigins:       []string{"*"},
					CustomApiResponseHeaders: apiHeaders,
					CustomUiResponseHeaders:  uiHeaders,
				},
				{
					Type:                     "tcp",
					Purpose:                  []string{"cluster"},
					CustomApiResponseHeaders: apiHeaders,
					CustomUiResponseHeaders:  uiHeaders,
				},
				{
					Type:                     "tcp",
					Purpose:                  []string{"ops"},
					TLSDisable:               true,
					CustomApiResponseHeaders: apiHeaders,
					CustomUiResponseHeaders:  uiHeaders,
				},
				{
					Type:                     "tcp",
					Purpose:                  []string{"proxy"},
					CustomApiResponseHeaders: apiHeaders,
					CustomUiResponseHeaders:  uiHeaders,
				},
			},
			Seals: []*configutil.KMS{
				{
					Type:    "aead",
					Purpose: []string{"root"},
					Config: map[string]string{
						"aead_type": "aes-gcm",
						"key_id":    "global_root",
					},
				},
				{
					Type:    "aead",
					Purpose: []string{"worker-auth"},
					Config: map[string]string{
						"aead_type": "aes-gcm",
						"key_id":    "global_worker-auth",
					},
				},
				{
					Type:    "aead",
					Purpose: []string{"bsr"},
					Config: map[string]string{
						"aead_type": "aes-gcm",
						"key_id":    "global_bsr",
					},
				},
				{
					Type:    "aead",
					Purpose: []string{"recovery"},
					Config: map[string]string{
						"aead_type": "aes-gcm",
						"key_id":    "global_recovery",
					},
				},
				{
					Type:    "aead",
					Purpose: []string{"worker-auth-storage"},
					Config: map[string]string{
						"aead_type": "aes-gcm",
						"key_id":    "worker-auth-storage",
					},
				},
			},
		},
		Controller: &Controller{
			Name:                    "dev-controller",
			Description:             "A default controller created in dev mode",
			ApiRateLimits:           make(ratelimit.Configs, 0),
			ApiRateLimiterMaxQuotas: ratelimit.DefaultLimiterMaxQuotas(),
		},
		DevController: true,
		Worker: &Worker{
			Name:                "w_1234567890",
			Description:         "A default worker created in dev mode",
			InitialUpstreams:    []string{"127.0.0.1"},
			InitialUpstreamsRaw: []any{"127.0.0.1"},
			Tags: map[string][]string{
				"type": {"dev", "local"},
			},
		},
	}

	exp.Listeners[0].RawConfig = actual.Listeners[0].RawConfig
	exp.Listeners[1].RawConfig = actual.Listeners[1].RawConfig
	exp.Listeners[2].RawConfig = actual.Listeners[2].RawConfig
	exp.Listeners[3].RawConfig = actual.Listeners[3].RawConfig
	exp.Seals[0].Config["key"] = actual.Seals[0].Config["key"]
	exp.Seals[1].Config["key"] = actual.Seals[1].Config["key"]
	exp.Seals[2].Config["key"] = actual.Seals[2].Config["key"]
	exp.Seals[3].Config["key"] = actual.Seals[3].Config["key"]
	exp.Seals[4].Config["key"] = actual.Seals[4].Config["key"]
	exp.DevControllerKey = actual.Seals[0].Config["key"]
	exp.DevWorkerAuthKey = actual.Seals[1].Config["key"]
	exp.DevBsrKey = actual.Seals[2].Config["key"]
	exp.DevRecoveryKey = actual.Seals[3].Config["key"]
	exp.DevWorkerAuthStorageKey = actual.Seals[4].Config["key"]
	exp.Worker.TagsRaw = actual.Worker.TagsRaw
	assert.Equal(t, exp, actual)
}

func TestDevWorkerCredentialStoragePath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name                           string
		devWorkerProvidedConfiguration string
		storagePath                    string
	}{
		{
			name: "Relative Storage Directory",
			devWorkerProvidedConfiguration: `
			listener "tcp" {
				purpose = "proxy"
			}

			worker {
				name = "w_1234567890"
				description = "A default worker created in dev mode"
				initial_upstreams = ["127.0.0.1"]
				tags {
					type = ["dev", "local"]
				}
				auth_storage_path = ".."
			}
			`,
			storagePath: "..",
		},
		{
			name: "Nonexistent Storage Directory",
			devWorkerProvidedConfiguration: `
			listener "tcp" {
				purpose = "proxy"
			}

			worker {
				name = "w_1234567890"
				description = "A default worker created in dev mode"
				initial_upstreams = ["127.0.0.1"]
				tags {
					type = ["dev", "local"]
				}
				auth_storage_path = "nonexistent_dir/here"
			}
			`,
			storagePath: "nonexistent_dir/here",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := Parse(devConfig + tt.devWorkerProvidedConfiguration)
			require.NoError(t, err)
			require.Equal(t, tt.storagePath, parsed.Worker.AuthStoragePath)
		})
	}
}

func TestDevWorkerRecordingStorageMinimumAvailableCapacity(t *testing.T) {
	t.Parallel()
	td := t.TempDir()
	tests := []struct {
		name                           string
		devWorkerProvidedConfiguration string
		storagePath                    string
		storageCapacity                string
		expectedDiskSpace              uint64
		expectedErrMsg                 string
	}{
		{
			name: "empty storage with empty capacity",
			devWorkerProvidedConfiguration: `
			listener "tcp" {
				purpose = "proxy"
			}

			worker {
				name = "w_1234567890"
				description = "A default worker created in dev mode"
				initial_upstreams = ["127.0.0.1"]
				tags {
					type = ["dev", "local"]
				}
			}
			`,
			expectedDiskSpace: 0,
			storagePath:       "",
		},
		{
			name: "empty storage path with set capacity",
			devWorkerProvidedConfiguration: `
			listener "tcp" {
				purpose = "proxy"
			}

			worker {
				name = "w_1234567890"
				description = "A default worker created in dev mode"
				initial_upstreams = ["127.0.0.1"]
				tags {
					type = ["dev", "local"]
				}
				recording_storage_minimum_available_capacity = "4kib"
			}
			`,
			expectedErrMsg: "recording_storage_path cannot be empty when providing recording_storage_minimum_available_capacity",
		},
		{
			name: "storage path with empty capacity defaults to 500mib",
			devWorkerProvidedConfiguration: fmt.Sprintf(`
			listener "tcp" {
				purpose = "proxy"
			}

			worker {
				name = "w_1234567890"
				description = "A default worker created in dev mode"
				initial_upstreams = ["127.0.0.1"]
				tags {
					type = ["dev", "local"]
				}
				recording_storage_path = "%v"
			}
			`, td),
			storagePath:       td,
			expectedDiskSpace: 524288000,
		},
		{
			name: "storage path with capacity string",
			devWorkerProvidedConfiguration: fmt.Sprintf(`
			listener "tcp" {
				purpose = "proxy"
			}

			worker {
				name = "w_1234567890"
				description = "A default worker created in dev mode"
				initial_upstreams = ["127.0.0.1"]
				tags {
					type = ["dev", "local"]
				}
				recording_storage_path = "%v"
				recording_storage_minimum_available_capacity = "4kib"
			}
			`, td),
			storagePath:       td,
			expectedDiskSpace: 4096,
		},
		{
			name: "storage path with raw byte value",
			devWorkerProvidedConfiguration: fmt.Sprintf(`
			listener "tcp" {
				purpose = "proxy"
			}

			worker {
				name = "w_1234567890"
				description = "A default worker created in dev mode"
				initial_upstreams = ["127.0.0.1"]
				tags {
					type = ["dev", "local"]
				}
				recording_storage_path = "%v"
				recording_storage_minimum_available_capacity = "4096"
			}
			`, td),
			storagePath:       td,
			expectedDiskSpace: 4096,
		},
		{
			name: "storage path with invalid capacity input",
			devWorkerProvidedConfiguration: fmt.Sprintf(`
			listener "tcp" {
				purpose = "proxy"
			}

			worker {
				name = "w_1234567890"
				description = "A default worker created in dev mode"
				initial_upstreams = ["127.0.0.1"]
				tags {
					type = ["dev", "local"]
				}
				recording_storage_path = "%v"
				recording_storage_minimum_available_capacity = "gib"
			}
			`, td),
			storagePath:    td,
			expectedErrMsg: "could not parse capacity from input",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := Parse(devConfig + tt.devWorkerProvidedConfiguration)
			if tt.expectedErrMsg != "" {
				require.Error(t, err)
				assert.ErrorContains(t, err, tt.expectedErrMsg)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.storagePath, parsed.Worker.RecordingStoragePath)
			assert.Equal(t, tt.expectedDiskSpace, parsed.Worker.RecordingStorageMinimumAvailableDiskSpace)
		})
	}
}

func TestDevWorkerRecordingStoragePath(t *testing.T) {
	t.Parallel()
	td := t.TempDir()
	tests := []struct {
		name                           string
		devWorkerProvidedConfiguration string
		storagePath                    string
	}{
		{
			name: "Relative Storage Directory",
			devWorkerProvidedConfiguration: `
			listener "tcp" {
				purpose = "proxy"
			}

			worker {
				name = "w_1234567890"
				description = "A default worker created in dev mode"
				initial_upstreams = ["127.0.0.1"]
				tags {
					type = ["dev", "local"]
				}
				recording_storage_path = ".."
			}
			`,
			storagePath: "..",
		},
		{
			name: "temp dir",
			devWorkerProvidedConfiguration: fmt.Sprintf(`
			listener "tcp" {
				purpose = "proxy"
			}

			worker {
				name = "w_1234567890"
				description = "A default worker created in dev mode"
				initial_upstreams = ["127.0.0.1"]
				tags {
					type = ["dev", "local"]
				}
				recording_storage_path = "%v"
			}
			`, td),
			storagePath: td,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := Parse(devConfig + tt.devWorkerProvidedConfiguration)
			require.NoError(t, err)
			require.Equal(t, tt.storagePath, parsed.Worker.RecordingStoragePath)
		})
	}
}

// TestDevControllerIpv6 validates that all listeners use an IPv6 address when
// the WithIPv6Enabled(true) option is passed into DevController. Other dev
// controller configurations are validated in TestDevController.
func TestDevControllerIpv6(t *testing.T) {
	require := require.New(t)

	actual, err := DevController(WithIPv6Enabled(true))
	require.NoError(err)

	// Expected an error here because PublicClusterAddr is not set.
	_, _, err = net.SplitHostPort(actual.Controller.PublicClusterAddr)
	require.Error(err)

	// Same here.
	publicAddr, port, err := util.SplitHostPort(actual.Controller.PublicClusterAddr)
	require.ErrorIs(err, util.ErrMissingPort)
	require.Empty(port)
	require.Empty(publicAddr)

	require.NotEmpty(actual.Listeners)
	for _, l := range actual.Listeners {
		addr, _, err := util.SplitHostPort(l.Address)
		require.ErrorIs(err, util.ErrMissingPort)
		require.NotEmpty(t, addr)

		ip := net.ParseIP(addr)
		require.NotNil(ip, "failed to parse listener address for %v", l.Purpose)
		require.NotNil(ip.To16(), "failed to convert address to IPv6 for %v, found %v", l.Purpose, addr)
	}
}

// TestDevWorkerIpv6 validates that all listeners use an IPv6 address when the
// WithIPv6Enabled(true) option is passed into DevWorker. Other dev worker
// configurations are validated in TestDevWorker.
func TestDevWorkerIpv6(t *testing.T) {
	require := require.New(t)

	actual, err := DevWorker(WithIPv6Enabled(true))
	require.NoError(err)

	// Expected an error here because PublicAddr does not have a port.
	_, _, err = net.SplitHostPort(actual.Worker.PublicAddr)
	require.Error(err)

	// util.SplitHostPort, however, can handle it when ports are missing.
	publicAddr, port, err := util.SplitHostPort(actual.Worker.PublicAddr)
	require.ErrorIs(err, util.ErrMissingPort)
	require.Empty(port)
	require.NotEmpty(t, publicAddr)

	ip := net.ParseIP(publicAddr)
	require.NotNil(ip, "failed to parse worker public address")
	require.NotNil(ip.To16(), "worker public address is not IPv6 %s", actual.Worker.PublicAddr)

	require.NotEmpty(actual.Listeners)
	for _, l := range actual.Listeners {
		addr, _, err := util.SplitHostPort(l.Address)
		require.ErrorIs(err, util.ErrMissingPort)
		require.NotEmpty(addr)

		ip := net.ParseIP(addr)
		require.NotNil(ip, "failed to parse listener address for %v", l.Purpose)
		require.NotNil(ip.To16(), "failed to convert address to IPv6 for %v, found %v", l.Purpose, addr)
	}
}

// TestDevCombinedIpv6 validates that all listeners use an IPv6 address when the
// WithIPv6Enabled(true) option is passed into DevCombined.
func TestDevCombinedIpv6(t *testing.T) {
	require := require.New(t)

	actual, err := DevCombined(WithIPv6Enabled(true))
	require.NoError(err)

	// Expected to fail because PublicAddr does not have a port.
	_, _, err = net.SplitHostPort(actual.Worker.PublicAddr)
	require.Error(err)
	// Expected to fail because PublicClusterAddr is not set.
	_, _, err = net.SplitHostPort(actual.Controller.PublicClusterAddr)
	require.Error(err)

	// util.SplitHostPort, however, can handle it when ports are missing.
	publicAddr, port, err := util.SplitHostPort(actual.Worker.PublicAddr)
	require.ErrorIs(err, util.ErrMissingPort)
	require.Empty(port)
	require.NotEmpty(publicAddr)

	ip := net.ParseIP(publicAddr)
	require.NotNil(ip, "failed to parse worker public address")
	require.NotNil(ip.To16(), "worker public address is not IPv6 %s", actual.Worker.PublicAddr)

	// Expected to fail because PublicClusterAddr is not set.
	publicAddr, port, err = util.SplitHostPort(actual.Controller.PublicClusterAddr)
	require.ErrorIs(err, util.ErrMissingPort)
	require.Empty(port)
	require.Empty(publicAddr)

	require.NotEmpty(actual.Listeners)
	for _, l := range actual.Listeners {
		addr, _, err := util.SplitHostPort(l.Address)
		require.ErrorIs(err, util.ErrMissingPort)
		require.NotEmpty(addr)

		ip := net.ParseIP(addr)
		require.NotNil(ip, "failed to parse listener address for %v", l.Purpose)
		require.NotNil(ip.To16(), "failed to convert address to IPv6 for %v, found %v", l.Purpose, addr)
	}
}

func TestDevKeyGeneration(t *testing.T) {
	t.Parallel()
	dk := DevKeyGeneration(WithRandomReader(rand.Reader))
	buf, err := base64.StdEncoding.DecodeString(dk)
	require.NoError(t, err)
	require.Len(t, buf, 32)
	require.NotEqual(t, dk, DevKeyGeneration())
}

func TestParsingName(t *testing.T) {
	t.Parallel()
	config := `
	controller {
		name = "%s"
	}
	worker {
		name = "%s"
	}
	`
	controllerEnv := "FOOENV"
	workerEnv := "BARENV"
	cases := []struct {
		name               string
		templateController string
		templateWorker     string
		envController      string
		envWorker          string
		expectedController string
		expectedWorker     string
	}{
		{
			name:               "no env",
			templateController: "foobar",
			templateWorker:     "test_worker_barfoo",
			expectedController: "foobar",
			expectedWorker:     "test_worker_barfoo",
		},
		{
			name:               "env",
			templateController: fmt.Sprintf("env://%s", controllerEnv),
			templateWorker:     fmt.Sprintf("env://%s", workerEnv),
			envController:      "foobar2",
			envWorker:          "env_name_barfoo2",
			expectedController: "foobar2",
			expectedWorker:     "env_name_barfoo2",
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envController != "" {
				os.Setenv(controllerEnv, tt.envController)
			}
			if tt.envWorker != "" {
				os.Setenv(workerEnv, tt.envWorker)
			}
			out, err := Parse(fmt.Sprintf(config, tt.templateController, tt.templateWorker))
			require.NoError(t, err)
			assert.Equal(t, tt.expectedController, out.Controller.Name)
			assert.Equal(t, tt.expectedWorker, out.Worker.Name)
		})
	}
}

func TestParsingSchedulerIntervals(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name                string
		config              string
		wantErr             bool
		wantMonitorInterval time.Duration
		wantRunJobInterval  time.Duration
	}{
		{
			name: "invalid-run-interval",
			config: `
controller {
  scheduler {
    job_run_interval = "hello"
  }
}
`,
			wantErr: true,
		},
		{
			name: "invalid-monitor-interval",
			config: `
controller {
  scheduler {
    monitor_interval = "hello"
  }
}
`,
			wantErr: true,
		},
		{
			name:                "valid-undefined",
			config:              `controller { scheduler {} }`,
			wantMonitorInterval: 0,
			wantRunJobInterval:  0,
		},
		{
			name: "run-job-interval",
			config: `
controller {
  scheduler {
    job_run_interval = "10m"
  }
}
`,
			wantMonitorInterval: 0,
			wantRunJobInterval:  10 * time.Minute,
		},
		{
			name: "monitor-interval",
			config: `
controller {
  scheduler {
    monitor_interval = "6h"
  }
}
`,
			wantMonitorInterval: 6 * time.Hour,
			wantRunJobInterval:  0,
		},
		{
			name: "both",
			config: `
controller {
  scheduler {
    monitor_interval = "7d"
    job_run_interval = "20s"
  }
}
`,
			wantMonitorInterval: 7 * 24 * time.Hour,
			wantRunJobInterval:  20 * time.Second,
		},
	}
	for _, tt := range cases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			out, err := Parse(tt.config)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantMonitorInterval, out.Controller.Scheduler.MonitorIntervalDuration)
			assert.Equal(t, tt.wantRunJobInterval, out.Controller.Scheduler.JobRunIntervalDuration)
		})
	}
}

func TestWorkerTags(t *testing.T) {
	defaultStateFn := func(t *testing.T, tags string) {
		t.Setenv("BOUNDARY_WORKER_TAGS", tags)
	}
	tests := []struct {
		name          string
		in            string
		stateFn       func(t *testing.T, tags string)
		actualTags    string
		expWorkerTags map[string][]string
		expErr        bool
		expErrStr     string
	}{
		{
			name: "tags in HCL",
			in: `
			worker {
				tags {
					type = ["dev", "local"]
					typetwo = "devtwo"
				}
			}`,
			expWorkerTags: map[string][]string{
				"type":    {"dev", "local"},
				"typetwo": {"devtwo"},
			},
			expErr: false,
		},
		{
			name: "tags in HCL key=value",
			in: `
			worker {
				tags = ["type=dev", "type=local", "typetwo=devtwo"]
			}
			`,
			expWorkerTags: map[string][]string{
				"type":    {"dev", "local"},
				"typetwo": {"devtwo"},
			},
			expErr: false,
		},
		{
			name: "no tags",
			in: `
			worker {
				name = "w_1234567890"
			}
			`,
			expWorkerTags: nil,
			expErr:        false,
		},
		{
			name: "empty tags",
			in: `
			worker {
				name = "w_1234567890"
				tags = {}
			}
			`,
			expWorkerTags: map[string][]string{},
			expErr:        false,
		},
		{
			name: "empty tags 2",
			in: `
			worker {
				name = "w_1234567890"
				tags = []
			}
			`,
			expWorkerTags: map[string][]string{},
			expErr:        false,
		},
		{
			name: "empty str",
			in: `
			worker {
				tags = ""
			}`,
			expWorkerTags: map[string][]string{},
			expErr:        false,
		},
		{
			name: "empty env var",
			in: `
			worker {
				tags = "env://BOUNDARY_WORKER_TAGS"
			}`,
			expWorkerTags: map[string][]string{},
			expErr:        false,
		},
		{
			name: "not a url - entire tags block",
			in: `
			worker {
				tags = "\x00"
			}`,
			expWorkerTags: map[string][]string{},
			expErr:        true,
			expErrStr:     `Error parsing worker tags: error parsing url ("parse \"\\x00\": net/url: invalid control character in URL"): not a url`,
		},
		{
			name: "not a url - key's value set to string",
			in: `
			worker {
				tags {
					type = "\x00"
				}
			}
			`,
			expWorkerTags: map[string][]string{
				"type": {"\x00"},
			},
			expErr: false,
		},
		{
			name: "one tag key",
			in: `
			worker {
				tags = "env://BOUNDARY_WORKER_TAGS"
			}`,
			stateFn:    defaultStateFn,
			actualTags: `type = ["dev", "local"]`,
			expWorkerTags: map[string][]string{
				"type": {"dev", "local"},
			},
			expErr: false,
		},
		{
			name: "multiple tag keys",
			in: `
			worker {
				tags = "env://BOUNDARY_WORKER_TAGS"
			}`,
			stateFn: defaultStateFn,
			actualTags: `
			type = ["dev", "local"]
			typetwo = ["devtwo", "localtwo"]
			`,
			expWorkerTags: map[string][]string{
				"type":    {"dev", "local"},
				"typetwo": {"devtwo", "localtwo"},
			},
			expErr: false,
		},
		{
			name: "comma in tag key string",
			in: `
			worker {
				tags {
					"key,"= ["value"],
				}
			}`,
			expErr:    true,
			expErrStr: `Tag key "key," cannot contain commas`,
		},
		{
			name: "comma in tag value string",
			in: `
			worker {
				tags {
					"key"= ["va,lue","value2"],
				}
			}`,
			expErr:    true,
			expErrStr: `Tag value "va,lue" for tag key "key" cannot contain commas`,
		},
		{
			name: "json tags - entire tags block",
			in: `
			worker {
				tags = "env://BOUNDARY_WORKER_TAGS"
			}`,
			stateFn: defaultStateFn,
			actualTags: `
			{
				"type": ["dev", "local"],
				"typetwo": ["devtwo", "localtwo"]
			}
			`,
			expWorkerTags: map[string][]string{
				"type":    {"dev", "local"},
				"typetwo": {"devtwo", "localtwo"},
			},
			expErr: false,
		},
		{
			name: "json tags - keys specified in the HCL file, values point to env/file",
			in: `
			worker {
				tags = {
					type = "env://BOUNDARY_WORKER_TAGS"
					typetwo = "env://BOUNDARY_WORKER_TAGS_TWO"
				}
			}`,
			stateFn: func(t *testing.T, tags string) {
				defaultStateFn(t, tags)
				t.Setenv("BOUNDARY_WORKER_TAGS_TWO", `["devtwo", "localtwo"]`)
			},
			actualTags: `["dev","local"]`,
			expWorkerTags: map[string][]string{
				"type":    {"dev", "local"},
				"typetwo": {"devtwo", "localtwo"},
			},
			expErr: false,
		},
		{
			name: "json tags - mix n' match",
			in: `
			worker {
				name = "web-prod-us-east-1"
				tags {
				  type = "env://BOUNDARY_WORKER_TYPE_TAGS"
				  typetwo = "file://type_two_tags.json"
				  typethree = ["devthree", "localthree"]
				}
			}
			`,
			stateFn: func(t *testing.T, tags string) {
				workerTypeTags := `["dev", "local"]`
				t.Setenv("BOUNDARY_WORKER_TYPE_TAGS", workerTypeTags)

				filepath := "./type_two_tags.json"
				err := os.WriteFile(filepath, []byte(`["devtwo", "localtwo"]`), 0o666)
				require.NoError(t, err)

				t.Cleanup(func() {
					err := os.Remove(filepath)
					require.NoError(t, err)
				})
			},
			expWorkerTags: map[string][]string{
				"type":      {"dev", "local"},
				"typetwo":   {"devtwo", "localtwo"},
				"typethree": {"devthree", "localthree"},
			},
			expErr: false,
		},
		{
			name: "bad json tags",
			in: `
			worker {
				tags = {
					type = "env://BOUNDARY_WORKER_TAGS"
					typetwo = "env://BOUNDARY_WORKER_TAGS"
				}
			}`,
			stateFn: defaultStateFn,
			actualTags: `
			{
				"type": ["dev", "local"],
				"typetwo": ["devtwo", "localtwo"]
			}
			`,
			expWorkerTags: nil,
			expErr:        true,
			expErrStr:     "Error unmarshaling env var/file contents: json: cannot unmarshal object into Go value of type []string",
		},
		{
			name: "no clean mapping to internal structures",
			in: `
			worker {
				tags = "env://BOUNDARY_WORKER_TAGS"
			}`,
			stateFn: defaultStateFn,
			actualTags: `
			worker {
				tags {
					type = "indeed"
				}
			}
			`,
			expErr:    true,
			expErrStr: "Error decoding the worker's tags: 1 error(s) decoding:\n\n* '[0][worker][0]' expected type 'string', got unconvertible type 'map[string]interface {}', value: 'map[tags:[map[type:indeed]]]'",
		},
		{
			name: "not HCL",
			in: `worker {
				tags = "env://BOUNDARY_WORKER_TAGS"
			}`,
			stateFn:    defaultStateFn,
			actualTags: `not_hcl`,
			expErr:     true,
			expErrStr:  "Error decoding raw worker tags: At 1:9: key 'not_hcl' expected start of object ('{') or assignment ('=')",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.stateFn != nil {
				tt.stateFn(t, tt.actualTags)
			}

			c, err := Parse(tt.in)
			if tt.expErr {
				require.EqualError(t, err, tt.expErrStr)
				require.Nil(t, c)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, c)
			require.NotNil(t, c.Worker)
			require.Equal(t, tt.expWorkerTags, c.Worker.Tags)
		})
	}
}

func TestController_EventingConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		config            []string
		wantEventerConfig *event.EventerConfig
		wantErr           string
	}{
		{
			name:              "default",
			wantEventerConfig: event.DefaultEventerConfig(),
		},
		{
			name: "audit-enabled",
			config: []string{`
			events {
				audit_enabled = true
			}
			`},
			wantEventerConfig: &event.EventerConfig{
				AuditEnabled:        true,
				ObservationsEnabled: false,
				Sinks: []*event.SinkConfig{
					event.DefaultSink(),
				},
			},
		},
		{
			name: "observations-enabled",
			config: []string{`
			events {
				observations_enabled = true
			}
			`},
			wantEventerConfig: &event.EventerConfig{
				AuditEnabled:        false,
				ObservationsEnabled: true,
				Sinks: []*event.SinkConfig{
					event.DefaultSink(),
				},
			},
		},
		{
			name: "no-sink-type-determined",
			config: []string{
				`events {
				audit_enabled = false
				observations_enabled = true
				sink {
					format = "cloudevents-json"
					name = "configured-sink"
					event_types = [ "audit", "observation" ]
				}
			}`,
			},
			wantErr: `error parsing "events": sink type could not be determined`,
		},
		{
			name: "sinks-configured",
			config: []string{
				`events {
				audit_enabled = false
				observations_enabled = true
				sink {
					type = "file"
					format = "cloudevents-json"
					name = "configured-sink"
					event_types = [ "audit", "observation" ]
					file {
						file_name = "file-name"
						rotate_duration = "2m"
					}
				}
				sink {
					type = "stderr"
					format = "hclog-text"
					name = "stderr-sink"
					event_types = [ "error" ]
				}
			}`,
				`events {
				audit_enabled = false
				observations_enabled = true
				sink "file" {
					format = "cloudevents-json"
					name = "configured-sink"
					event_types = [ "audit", "observation" ]
					file {
						file_name = "file-name"
						rotate_duration = "2m"
					}
				}
				sink "stderr" {
					format = "hclog-text"
					name = "stderr-sink"
					event_types = [ "error" ]
				}
			}`,
				`events {
				audit_enabled = false
				observations_enabled = true
				sink {
					format = "cloudevents-json"
					name = "configured-sink"
					event_types = [ "audit", "observation" ]
					file {
						file_name = "file-name"
						rotate_duration = "2m"
					}
				}
				sink {
					format = "hclog-text"
					name = "stderr-sink"
					event_types = [ "error" ]
					stderr = {}
				}
			}`,
				`{
					"events": {
						"audit_enabled": false,
						"observations_enabled": true,
						"sink": [
							{
								"type": "file",
								"format": "cloudevents-json",
								"name": "configured-sink",
								"event_types": ["audit", "observation"],
								"file": {
									"file_name": "file-name",
									"rotate_duration": "2m"
								}
							},
							{
								"format": "hclog-text",
								"name": "stderr-sink",
								"event_types": ["error"],
								"stderr": {}
							}
						]
					}
				}`,
			},
			wantEventerConfig: &event.EventerConfig{
				AuditEnabled:        false,
				ObservationsEnabled: true,
				Sinks: []*event.SinkConfig{
					{
						Type:       "file",
						Name:       "configured-sink",
						Format:     "cloudevents-json",
						EventTypes: []event.Type{"audit", "observation"},
						FileConfig: &event.FileSinkTypeConfig{
							FileName:          "file-name",
							RotateDurationHCL: "2m",
							RotateDuration:    2 * time.Minute,
						},
					},
					{
						Type:         "stderr",
						Name:         "stderr-sink",
						Format:       "hclog-text",
						EventTypes:   []event.Type{"error"},
						StderrConfig: &event.StderrSinkTypeConfig{},
					},
				},
			},
		},
		{
			name: "audit_config",
			config: []string{
				`events {
					audit_enabled = true
					sink {
						name = "audit-sink"
						format = "cloudevents-json"
						event_types = ["audit"]
						file {
							file_name = "audit.log"
						}
						audit_config {
							audit_filter_overrides {
								sensitive = ""
								secret    = "hmac-sha256"
							}
						}
					}
				}`,
			},
			wantEventerConfig: &event.EventerConfig{
				AuditEnabled: true,
				Sinks: []*event.SinkConfig{
					{
						Type:       "file",
						Name:       "audit-sink",
						Format:     "cloudevents-json",
						EventTypes: []event.Type{"audit"},
						FileConfig: &event.FileSinkTypeConfig{
							FileName: "audit.log",
						},
						AuditConfig: &event.AuditConfig{
							FilterOverridesHCL: map[string]string{
								"sensitive": "",
								"secret":    "hmac-sha256",
							},
							FilterOverrides: event.AuditFilterOperations{
								event.SensitiveClassification: event.NoOperation,
								event.SecretClassification:    event.HmacSha256Operation,
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			for i, conf := range tt.config {
				c, err := Parse(conf)
				if tt.wantErr != "" {
					require.Error(err)
					assert.Empty(c)
					assert.Equal(tt.wantErr, err.Error(), "config %d want %q and got %q", i, tt.wantErr, err.Error())
					return
				}
				require.NoError(err)
				assert.NotEmpty(c)
				assert.Equal(tt.wantEventerConfig, c.Eventing)
			}
		})
	}
}

func TestWorkerUpstreams(t *testing.T) {
	tests := []struct {
		name               string
		in                 string
		stateFn            func(t *testing.T)
		expWorkerUpstreams []string
		expErr             bool
		expErrIs           error
		expErrStr          string
	}{
		{
			name: "No Upstreams",
			in: `
			worker {
				name = "test"
			}
			`,
			expWorkerUpstreams: nil,
			expErr:             false,
		},
		{
			name: "ipv4 Upstream",
			in: `
			worker {
				name = "test"
				initial_upstreams = ["127.0.0.1"]
			}
			`,
			expWorkerUpstreams: []string{"127.0.0.1"},
			expErr:             false,
		},
		{
			name: "ipv6 Upstream",
			in: `
			worker {
				name = "test"
				initial_upstreams = ["2001:4860:4860:0:0:0:0:8888"]
			}
			`,
			expWorkerUpstreams: []string{"2001:4860:4860::8888"},
			expErr:             false,
		},
		{
			name: "abbreviated ipv6 Upstream",
			in: `
			worker {
				name = "test"
				initial_upstreams = ["2001:4860:4860::8888"]
			}
			`,
			expWorkerUpstreams: []string{"2001:4860:4860::8888"},
			expErr:             false,
		},
		{
			name: "Multiple Upstreams",
			in: `
			worker {
				name = "test"
				initial_upstreams = ["127.0.0.1", "127.0.0.2", "127.0.0.3"]
			}
			`,
			expWorkerUpstreams: []string{"127.0.0.1", "127.0.0.2", "127.0.0.3"},
			expErr:             false,
		},
		{
			name: "Using env var",
			in: `
			worker {
				name = "test"
				initial_upstreams = "env://BOUNDARY_WORKER_UPSTREAMS"
			}
			`,
			stateFn:            func(t *testing.T) { t.Setenv("BOUNDARY_WORKER_UPSTREAMS", `["127.0.0.1", "127.0.0.2", "127.0.0.3"]`) },
			expWorkerUpstreams: []string{"127.0.0.1", "127.0.0.2", "127.0.0.3"},
			expErr:             false,
		},
		{
			name: "Using env var - invalid input 1",
			in: `
			worker {
				name = "test"
				initial_upstreams = "env://BOUNDARY_WORKER_UPSTREAMS"
			}
			`,
			stateFn: func(t *testing.T) {
				upstreams := `
				worker {
					initial_upstreams = ["127.0.0.1"]
				}
				`
				t.Setenv("BOUNDARY_WORKER_UPSTREAMS", upstreams)
			},
			expWorkerUpstreams: nil,
			expErr:             true,
			expErrStr:          "Failed to parse worker upstreams: failed to unmarshal env/file contents: invalid character 'w' looking for beginning of value",
		},
		{
			name: "Using env var - invalid input 2",
			in: `
			worker {
				name = "test"
				initial_upstreams = "env://BOUNDARY_WORKER_UPSTREAMS"
			}
			`,
			stateFn:            func(t *testing.T) { t.Setenv("BOUNDARY_WORKER_UPSTREAMS", `initial_upstreams = ["127.0.0.1"]`) },
			expWorkerUpstreams: nil,
			expErr:             true,
			expErrStr:          "Failed to parse worker upstreams: failed to unmarshal env/file contents: invalid character 'i' looking for beginning of value",
		},
		{
			name: "Duplicate field",
			in: `
			worker {
				name = "test"
				initial_upstreams = {
					ip = "127.0.0.1"
					ip = "127.0.0.2"
				}
			}
			`,
			expWorkerUpstreams: nil,
			expErr:             true,
			expErrStr:          "The argument \"ip\" at 6:6 was already set. Each argument can only be defined once",
		},
		{
			name: "Worker initial_upstreams set to invalid url",
			in: `
			worker {
				name = "test"
				initial_upstreams = "env://\x00"
			}`,
			expWorkerUpstreams: nil,
			expErr:             true,
			expErrIs:           parseutil.ErrNotAUrl,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.stateFn != nil {
				tt.stateFn(t)
			}

			c, err := Parse(tt.in)
			if tt.expErr {
				if tt.expErrIs != nil {
					require.ErrorIs(t, err, tt.expErrIs)
				} else {
					require.EqualError(t, err, tt.expErrStr)
				}
				require.Nil(t, c)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, c)
			require.NotNil(t, c.Worker)
			require.EqualValues(t, tt.expWorkerUpstreams, c.Worker.InitialUpstreams)
		})
	}
}

func TestControllerDescription(t *testing.T) {
	tests := []struct {
		name           string
		in             string
		envDescription string
		expDescription string
		expErr         bool
		expErrStr      string
	}{
		{
			name: "Valid controller description from env var",
			in: `
			controller {
				description = "env://CONTROLLER_DESCRIPTION"
			}`,
			envDescription: "Test controller description",
			expDescription: "Test controller description",
			expErr:         false,
		}, {
			name: "Invalid controller description from env var",
			in: `
			controller {
				description = "\uTest controller description"
			}`,
			expErr:    true,
			expErrStr: "At 3:22: illegal char escape",
		}, {
			name: "Not a URL, non-printable description",
			in: `
			controller {
				description = "\x00" 
			}`,
			expErr:    true,
			expErrStr: "Controller description contains non-printable characters",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("CONTROLLER_DESCRIPTION", tt.envDescription)
			c, err := Parse(tt.in)
			if tt.expErr {
				require.EqualError(t, err, tt.expErrStr)
				require.Nil(t, c)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, c)
			require.NotNil(t, c.Controller)
			require.Equal(t, tt.expDescription, c.Controller.Description)
		})
	}
}

func TestControllerApiRateLimits(t *testing.T) {
	tests := []struct {
		name      string
		in        string
		expLimits ratelimit.Configs
		expErr    bool
		expErrStr string
	}{
		{
			name: "Single Rate limit",
			in: `
			controller {
				api_rate_limit {
					resources = ["*"]
					actions   = ["*"]
					per       = "total"
					limit     = 50
					period    = "1m"
				}
			}`,
			expLimits: ratelimit.Configs{
				{
					Resources: []string{"*"},
					Actions:   []string{"*"},
					Per:       "total",
					Limit:     50,
					PeriodHCL: "1m",
					Period:    time.Minute,
					Unlimited: false,
				},
			},
			expErr: false,
		},
		{
			name: "Single Rate with name",
			in: `
			controller {
				api_rate_limit "default" {
					resources = ["*"]
					actions   = ["*"]
					per       = "total"
					limit     = 50
					period    = "1m"
				}
			}`,
			expLimits: ratelimit.Configs{
				{
					Resources: []string{"*"},
					Actions:   []string{"*"},
					Per:       "total",
					Limit:     50,
					PeriodHCL: "1m",
					Period:    time.Minute,
					Unlimited: false,
				},
			},
			expErr: false,
		},
		{
			name: "Multiple Rate limit",
			in: `
			controller {
				api_rate_limit {
					resources = ["*"]
					actions   = ["*"]
					per       = "total"
					limit     = 50
					period    = "1m"
				}

				api_rate_limit {
					resources = ["*"]
					actions   = ["list"]
					per       = "total"
					limit     = 20
					period    = "1m"
				}
			}`,
			expLimits: ratelimit.Configs{
				{
					Resources: []string{"*"},
					Actions:   []string{"*"},
					Per:       "total",
					Limit:     50,
					PeriodHCL: "1m",
					Period:    time.Minute,
					Unlimited: false,
				},
				{
					Resources: []string{"*"},
					Actions:   []string{"list"},
					Per:       "total",
					Limit:     20,
					PeriodHCL: "1m",
					Period:    time.Minute,
					Unlimited: false,
				},
			},
			expErr: false,
		},
		{
			name: "Multiple Rate limit with names",
			in: `
			controller {
				api_rate_limit "default" {
					resources = ["*"]
					actions   = ["*"]
					per       = "total"
					limit     = 50
					period    = "1m"
				}

				api_rate_limit "default-list" {
					resources = ["*"]
					actions   = ["list"]
					per       = "total"
					limit     = 20
					period    = "1m"
				}
			}`,
			expLimits: ratelimit.Configs{
				{
					Resources: []string{"*"},
					Actions:   []string{"*"},
					Per:       "total",
					Limit:     50,
					PeriodHCL: "1m",
					Period:    time.Minute,
					Unlimited: false,
				},
				{
					Resources: []string{"*"},
					Actions:   []string{"list"},
					Per:       "total",
					Limit:     20,
					PeriodHCL: "1m",
					Period:    time.Minute,
					Unlimited: false,
				},
			},
			expErr: false,
		},
		{
			name: "Multiple Rate limit with name and no name",
			in: `
			controller {
				api_rate_limit {
					resources = ["*"]
					actions   = ["*"]
					per       = "total"
					limit     = 50
					period    = "1m"
				}

				api_rate_limit "list" {
					resources = ["*"]
					actions   = ["list"]
					per       = "total"
					limit     = 20
					period    = "1m"
				}
			}`,
			expLimits: ratelimit.Configs{
				{
					Resources: []string{"*"},
					Actions:   []string{"*"},
					Per:       "total",
					Limit:     50,
					PeriodHCL: "1m",
					Period:    time.Minute,
					Unlimited: false,
				},
				{
					Resources: []string{"*"},
					Actions:   []string{"list"},
					Per:       "total",
					Limit:     20,
					PeriodHCL: "1m",
					Period:    time.Minute,
					Unlimited: false,
				},
			},
			expErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := Parse(tt.in)
			if tt.expErr {
				require.EqualError(t, err, tt.expErrStr)
				require.Nil(t, c)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, c)
			require.NotNil(t, c.Controller)
			require.Equal(t, tt.expLimits, c.Controller.ApiRateLimits)
		})
	}
}

func TestWorkerDescription(t *testing.T) {
	tests := []struct {
		name           string
		in             string
		envDescription string
		expDescription string
		expErr         bool
		expErrStr      string
	}{
		{
			name: "Valid worker description from env var",
			in: `
			worker {
				description = "env://WORKER_DESCRIPTION"
			}`,
			envDescription: "Test worker description",
			expDescription: "Test worker description",
			expErr:         false,
		}, {
			name: "Invalid worker description",
			in: `
			worker {
				description = "\uTest worker description"
			}`,
			expErr:    true,
			expErrStr: "At 3:22: illegal char escape",
		}, {
			name: "Not a URL, non-printable description",
			in: `
			worker {
				description = "\x00"
			}`,
			expErr:    true,
			expErrStr: "Worker description contains non-printable characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("WORKER_DESCRIPTION", tt.envDescription)
			c, err := Parse(tt.in)
			if tt.expErr {
				require.EqualError(t, err, tt.expErrStr)
				require.Nil(t, c)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, c)
			require.NotNil(t, c.Worker)
			require.Equal(t, tt.expDescription, c.Worker.Description)
		})
	}
}

func TestPluginExecutionDir(t *testing.T) {
	tests := []struct {
		name                  string
		in                    string
		envPluginExecutionDir string
		expPluginExecutionDir string
		expErr                bool
		expErrStr             string
	}{
		{
			name: "Valid plugin execution dir from env var",
			in: `
			plugins {
  				execution_dir = "env://PLUGIN_EXEC_DIR"
			}`,
			envPluginExecutionDir: `/var/run/boundary/plugin-exec`,
			expPluginExecutionDir: `/var/run/boundary/plugin-exec`,
			expErr:                false,
		}, {
			name: "Invalid plugin execution dir  from env var",
			in: `
			plugins {
  				execution_dir ="\ubad plugin directory"
			}`,
			expErr:    true,
			expErrStr: "At 3:28: illegal char escape",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("PLUGIN_EXEC_DIR", tt.envPluginExecutionDir)
			p, err := Parse(tt.in)
			if tt.expErr {
				require.EqualError(t, err, tt.expErrStr)
				require.Nil(t, p)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, p)
			require.NotNil(t, p.Plugins)
			require.Equal(t, tt.expPluginExecutionDir, p.Plugins.ExecutionDir)
		})
	}
}

func TestDatabaseMaxConnections(t *testing.T) {
	tests := []struct {
		name                  string
		in                    string
		envMaxOpenConnections string
		expMaxOpenConnections int
		expErr                bool
		expErrStr             string
	}{
		{
			name: "Valid integer value",
			in: `
			controller {
				name = "example-controller"
				database {
					max_open_connections = 5
			  	}
			}`,
			expMaxOpenConnections: 5,
			expErr:                false,
		},
		{
			name: "Valid string value",
			in: `
			controller {
				name = "example-controller"
				database {
					max_open_connections = "5"
			  	}
			}`,
			expMaxOpenConnections: 5,
			expErr:                false,
		},
		{
			name: "Invalid value string",
			in: `
			controller {
				name = "example-controller"
				database {
					max_open_connections = "string bad"
				}
			}`,
			expErr: true,
			expErrStr: "Database max open connections value is not an int: " +
				"strconv.Atoi: parsing \"string bad\": invalid syntax",
		},
		{
			name: "Invalid value type",
			in: `
			controller {
				name = "example-controller"
				database {
					max_open_connections = false
				}
			}`,
			expErr:    true,
			expErrStr: "Database max open connections: unsupported type \"bool\"",
		},
		{
			name: "Valid env var",
			in: `
			controller {
				name = "example-controller"
				database {
					max_open_connections = "env://ENV_MAX_CONN"
			  	}
			}`,
			expMaxOpenConnections: 8,
			envMaxOpenConnections: "8",
			expErr:                false,
		},
		{
			name: "Invalid env var",
			in: `
			controller {
				name = "example-controller"
				database {
					max_open_connections = "env://ENV_MAX_CONN"
			  	}
			}`,
			envMaxOpenConnections: "bogus value",
			expErr:                true,
			expErrStr: "Database max open connections value is not an int: " +
				"strconv.Atoi: parsing \"bogus value\": invalid syntax",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("ENV_MAX_CONN", tt.envMaxOpenConnections)
			c, err := Parse(tt.in)
			if tt.expErr {
				require.EqualError(t, err, tt.expErrStr)
				require.Nil(t, c)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, c)
			require.NotNil(t, c.Controller)
			require.NotNil(t, c.Controller.Database)
			require.Equal(t, tt.expMaxOpenConnections, c.Controller.Database.MaxOpenConnections)
		})
	}
}

func TestDatabaseMaxIdleConnections(t *testing.T) {
	tests := []struct {
		name                  string
		in                    string
		envMaxIdleConnections string
		expMaxIdleConnections int
		expErr                bool
		expErrStr             string
	}{
		{
			name: "Valid integer value",
			in: `
			controller {
				name = "example-controller"
				database {
					max_idle_connections = 5
			  	}
			}`,
			expMaxIdleConnections: 5,
			expErr:                false,
		},
		{
			name: "Valid integer string",
			in: `
			controller {
				name = "example-controller"
				database {
					max_idle_connections = "5"
			  	}
			}`,
			expMaxIdleConnections: 5,
			expErr:                false,
		},
		{
			name: "Invalid value string",
			in: `
			controller {
				name = "example-controller"
				database {
					max_idle_connections = "string bad"
				}
			}`,
			expErr: true,
			expErrStr: "Database max idle connections value is not a uint: " +
				"strconv.Atoi: parsing \"string bad\": invalid syntax",
		},
		{
			name: "Invalid value type",
			in: `
			controller {
				name = "example-controller"
				database {
					max_idle_connections = false
				}
			}`,
			expErr:    true,
			expErrStr: "Database max idle connections: unsupported type \"bool\"",
		},
		{
			name: "Valid env var",
			in: `
			controller {
				name = "example-controller"
				database {
					max_idle_connections = "env://ENV_MAX_IDLE_CONN"
			  	}
			}`,
			expMaxIdleConnections: 8,
			envMaxIdleConnections: "8",
			expErr:                false,
		},
		{
			name: "Invalid env var",
			in: `
			controller {
				name = "example-controller"
				database {
					max_idle_connections = "env://ENV_MAX_IDLE_CONN"
			  	}
			}`,
			envMaxIdleConnections: "bogus value",
			expErr:                true,
			expErrStr: "Database max idle connections value is not a uint: " +
				"strconv.Atoi: parsing \"bogus value\": invalid syntax",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("ENV_MAX_IDLE_CONN", tt.envMaxIdleConnections)
			c, err := Parse(tt.in)
			if tt.expErr {
				require.EqualError(t, err, tt.expErrStr)
				require.Nil(t, c)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, c)
			require.NotNil(t, c.Controller)
			require.NotNil(t, c.Controller.Database)
			require.Equal(t, tt.expMaxIdleConnections, *c.Controller.Database.MaxIdleConnections)
		})
	}
}

func TestDatabaseConnMaxIdleTimeDuration(t *testing.T) {
	tests := []struct {
		name                       string
		in                         string
		envConnMaxIdleTimeDuration string
		expConnMaxIdleTimeDuration time.Duration
		expErr                     bool
		expErrStr                  string
	}{
		{
			name: "Valid duration value",
			in: `
			controller {
				name = "example-controller"
				database {
					max_idle_time = "5m"
			  	}
			}`,
			expConnMaxIdleTimeDuration: time.Minute * 5,
			expErr:                     false,
		},
		{
			name:                       "Valid env var value",
			envConnMaxIdleTimeDuration: "5m",
			in: `
			controller {
				name = "example-controller"
				database {
					max_idle_time = "env://ENV_CONN_MAX_IDLE_TIME"
			  	}
			}`,
			expConnMaxIdleTimeDuration: time.Minute * 5,
			expErr:                     false,
		},
		{
			name: "Invalid value string",
			in: `
			controller {
				name = "example-controller"
				database {
					max_idle_time = "string bad"
				}
			}`,
			expErr: true,
			expErrStr: "Connection max idle time is not a duration: " +
				"strconv.ParseInt: parsing \"string ba\": invalid syntax",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("ENV_CONN_MAX_IDLE_TIME", tt.envConnMaxIdleTimeDuration)
			c, err := Parse(tt.in)
			if tt.expErr {
				require.EqualError(t, err, tt.expErrStr)
				require.Nil(t, c)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, c)
			require.NotNil(t, c.Controller)
			require.NotNil(t, c.Controller.Database)
			require.Equal(t, tt.expConnMaxIdleTimeDuration, *c.Controller.Database.ConnMaxIdleTimeDuration)
		})
	}
}

func TestDatabaseSkipSharedLockAcquisition(t *testing.T) {
	tests := []struct {
		name                         string
		in                           string
		expSkipSharedLockAcquisition bool
	}{
		{
			name: "not set",
			in: `
			controller {
				name = "example-controller"
				database {
			  	}
			}`,
			expSkipSharedLockAcquisition: false,
		},
		{
			name: "set",
			in: `
			controller {
				name = "example-controller"
				database {
					skip_shared_lock_acquisition = true
			  	}
			}`,
			expSkipSharedLockAcquisition: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := Parse(tt.in)
			require.NoError(t, err)
			require.NotNil(t, c)
			require.NotNil(t, c.Controller)
			require.NotNil(t, c.Controller.Database)
			require.Equal(t, tt.expSkipSharedLockAcquisition, c.Controller.Database.SkipSharedLockAcquisition)
		})
	}
}

func TestSetupControllerPublicClusterAddress(t *testing.T) {
	tests := []struct {
		name                    string
		inputConfig             *Config
		inputFlagValue          string
		stateFn                 func(t *testing.T)
		expErr                  bool
		expErrStr               string
		expPublicClusterAddress string
	}{
		{
			name: "nil controller",
			inputConfig: &Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Controller: nil,
			},
			inputFlagValue:          "",
			expErr:                  false,
			expErrStr:               "",
			expPublicClusterAddress: ":9201",
		},
		{
			name: "setting public cluster address directly with ipv4",
			inputConfig: &Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Controller: &Controller{
					PublicClusterAddr: "127.0.0.1",
				},
			},
			inputFlagValue:          "",
			expErr:                  false,
			expErrStr:               "",
			expPublicClusterAddress: "127.0.0.1:9201",
		},
		{
			name: "setting public cluster address directly with ipv4:port",
			inputConfig: &Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Controller: &Controller{
					PublicClusterAddr: "127.0.0.1:8080",
				},
			},
			inputFlagValue:          "",
			expErr:                  false,
			expErrStr:               "",
			expPublicClusterAddress: "127.0.0.1:8080",
		},
		{
			name: "setting public cluster address directly with ipv6",
			inputConfig: &Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Controller: &Controller{
					PublicClusterAddr: "2001:4860:4860:0:0:0:0:8888",
				},
			},
			inputFlagValue:          "",
			expErr:                  false,
			expErrStr:               "",
			expPublicClusterAddress: "[2001:4860:4860::8888]:9201",
		},
		{
			name: "setting public cluster address directly with ipv6:port",
			inputConfig: &Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Controller: &Controller{
					PublicClusterAddr: "[2001:4860:4860:0:0:0:0:8888]:8080",
				},
			},
			inputFlagValue:          "",
			expErr:                  false,
			expErrStr:               "",
			expPublicClusterAddress: "[2001:4860:4860::8888]:8080",
		},
		{
			name: "setting public cluster address directly with abbreviated ipv6",
			inputConfig: &Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Controller: &Controller{
					PublicClusterAddr: "2001:4860:4860::8888",
				},
			},
			inputFlagValue:          "",
			expErr:                  false,
			expErrStr:               "",
			expPublicClusterAddress: "[2001:4860:4860::8888]:9201",
		},
		{
			name: "setting public cluster address directly with abbreviated ipv6:port",
			inputConfig: &Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Controller: &Controller{
					PublicClusterAddr: "[2001:4860:4860::8888]:8080",
				},
			},
			inputFlagValue:          "",
			expErr:                  false,
			expErrStr:               "",
			expPublicClusterAddress: "[2001:4860:4860::8888]:8080",
		},
		{
			name: "setting public cluster address to env var",
			inputConfig: &Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Controller: &Controller{
					PublicClusterAddr: "env://TEST_ENV_VAR_FOR_CONTROLLER_ADDR",
				},
			},
			inputFlagValue: "",
			stateFn: func(t *testing.T) {
				t.Setenv("TEST_ENV_VAR_FOR_CONTROLLER_ADDR", "127.0.0.1:8080")
			},
			expErr:                  false,
			expErrStr:               "",
			expPublicClusterAddress: "127.0.0.1:8080",
		},
		{
			name: "setting public cluster address to env var that points to template",
			inputConfig: &Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Controller: &Controller{
					PublicClusterAddr: "env://TEST_ENV_VAR_FOR_CONTROLLER_ADDR",
				},
			},
			inputFlagValue: "",
			stateFn: func(t *testing.T) {
				t.Setenv("TEST_ENV_VAR_FOR_CONTROLLER_ADDR", `{{ GetAllInterfaces | include "flags" "loopback" | include "type" "IPV4" | join "address" " " }}`)
			},
			expErr:                  false,
			expErrStr:               "",
			expPublicClusterAddress: "127.0.0.1:9201",
		},
		{
			name: "setting public cluster address to ip template",
			inputConfig: &Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Controller: &Controller{
					PublicClusterAddr: `{{ GetAllInterfaces | include "flags" "loopback" | include "type" "IPV4" | join "address" " " }}`,
				},
			},
			inputFlagValue:          "",
			expErr:                  false,
			expErrStr:               "",
			expPublicClusterAddress: "127.0.0.1:9201",
		},
		{
			name: "setting public cluster address to multiline ip template",
			inputConfig: &Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Controller: &Controller{
					PublicClusterAddr: `{{ with $local := GetAllInterfaces | include "flags" "loopback" | include "type" "IPV4" -}}
					{{- $local | join "address" " " -}}
				  {{- end }}`,
				},
			},
			inputFlagValue:          "",
			expErr:                  false,
			expErrStr:               "",
			expPublicClusterAddress: "127.0.0.1:9201",
		},
		{
			name: "using flag value with ip only",
			inputConfig: &Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Controller: &Controller{},
			},
			inputFlagValue:          "127.0.0.1",
			expErr:                  false,
			expErrStr:               "",
			expPublicClusterAddress: "127.0.0.1:9201",
		},
		{
			name: "using flag value with ip:port",
			inputConfig: &Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Controller: &Controller{},
			},
			inputFlagValue:          "127.0.0.1:8080",
			expErr:                  false,
			expErrStr:               "",
			expPublicClusterAddress: "127.0.0.1:8080",
		},
		{
			name: "using flag value with ip template",
			inputConfig: &Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Controller: &Controller{},
			},
			inputFlagValue:          `{{ GetAllInterfaces | include "flags" "loopback" | include "type" "IPV4" | join "address" " " }}`,
			expErr:                  false,
			expErrStr:               "",
			expPublicClusterAddress: "127.0.0.1:9201",
		},
		{
			name: "using flag value with multiline ip template",
			inputConfig: &Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Controller: &Controller{},
			},
			inputFlagValue: `{{ with $local := GetAllInterfaces | include "flags" "loopback" | include "type" "IPV4" -}}
			  {{- $local | join "address" " " -}}
			{{- end }}`,
			expErr:                  false,
			expErrStr:               "",
			expPublicClusterAddress: "127.0.0.1:9201",
		},
		{
			name: "using flag value to point to env var with ip only",
			inputConfig: &Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Controller: &Controller{},
			},
			inputFlagValue: "env://TEST_ENV_VAR_FOR_CONTROLLER_ADDR",
			stateFn: func(t *testing.T) {
				t.Setenv("TEST_ENV_VAR_FOR_CONTROLLER_ADDR", "127.0.0.1")
			},
			expErr:                  false,
			expErrStr:               "",
			expPublicClusterAddress: "127.0.0.1:9201",
		},
		{
			name: "using flag value to point to env var with ip:port",
			inputConfig: &Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Controller: &Controller{},
			},
			inputFlagValue: "env://TEST_ENV_VAR_FOR_CONTROLLER_ADDR",
			stateFn: func(t *testing.T) {
				t.Setenv("TEST_ENV_VAR_FOR_CONTROLLER_ADDR", "127.0.0.1:8080")
			},
			expErr:                  false,
			expErrStr:               "",
			expPublicClusterAddress: "127.0.0.1:8080",
		},
		{
			name: "read address from listeners ipv4 only",
			inputConfig: &Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{
						{Purpose: []string{"cluster"}, Address: "127.0.0.1"},
					},
				},
				Controller: &Controller{},
			},
			expErr:                  false,
			expErrStr:               "",
			expPublicClusterAddress: "127.0.0.1:9201",
		},
		{
			name: "read address from listeners ipv4:port",
			inputConfig: &Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{
						{Purpose: []string{"cluster"}, Address: "127.0.0.1:8080"},
					},
				},
				Controller: &Controller{},
			},
			expErr:                  false,
			expErrStr:               "",
			expPublicClusterAddress: "127.0.0.1:8080",
		},
		{
			name: "read address from listeners ipv6 only",
			inputConfig: &Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{
						{Purpose: []string{"cluster"}, Address: "2001:4860:4860:0:0:0:0:8888"},
					},
				},
				Controller: &Controller{},
			},
			expErr:                  false,
			expErrStr:               "",
			expPublicClusterAddress: "[2001:4860:4860::8888]:9201",
		},
		{
			name: "read address from listeners ipv6:port",
			inputConfig: &Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{
						{Purpose: []string{"cluster"}, Address: "[2001:4860:4860::8888]:8080"},
					},
				},
				Controller: &Controller{},
			},
			expErr:                  false,
			expErrStr:               "",
			expPublicClusterAddress: "[2001:4860:4860::8888]:8080",
		},
		{
			name: "read address from listeners abbreviated ipv6 only",
			inputConfig: &Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{
						{Purpose: []string{"cluster"}, Address: "2001:4860:4860::8888"},
					},
				},
				Controller: &Controller{},
			},
			expErr:                  false,
			expErrStr:               "",
			expPublicClusterAddress: "[2001:4860:4860::8888]:9201",
		},
		{
			name: "read address from listeners abbreviated ipv6:port",
			inputConfig: &Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{
						{Purpose: []string{"cluster"}, Address: "[2001:4860:4860::8888]:8080"},
					},
				},
				Controller: &Controller{},
			},
			expErr:                  false,
			expErrStr:               "",
			expPublicClusterAddress: "[2001:4860:4860::8888]:8080",
		},
		{
			name: "read address from listeners is ignored on different purpose",
			inputConfig: &Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{
						{Purpose: []string{"somethingelse"}, Address: "127.0.0.1:8080"},
					},
				},
				Controller: &Controller{},
			},
			expErr:                  false,
			expErrStr:               "",
			expPublicClusterAddress: ":9201",
		},
		{
			name: "using flag value to point to nonexistent file",
			inputConfig: &Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Controller: &Controller{},
			},
			inputFlagValue:          "file://this_doesnt_exist_for_sure",
			expErr:                  true,
			expErrStr:               "Error parsing public cluster addr: error reading file at file://this_doesnt_exist_for_sure: open this_doesnt_exist_for_sure: no such file or directory",
			expPublicClusterAddress: "",
		},
		{
			name: "using flag value to provoke error in SplitHostPort",
			inputConfig: &Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Controller: &Controller{},
			},
			inputFlagValue:          "abc::123:::",
			expErr:                  true,
			expErrStr:               "Error splitting public cluster adddress host/port: too many colons in address",
			expPublicClusterAddress: "",
		},
		{
			name: "bad ip template",
			inputConfig: &Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Controller: &Controller{},
			},
			inputFlagValue:          "{{ somethingthatdoesntexist }}",
			expErr:                  true,
			expErrStr:               "Error parsing IP template on controller public cluster addr: unable to parse address template \"{{ somethingthatdoesntexist }}\": unable to parse template \"{{ somethingthatdoesntexist }}\": template: sockaddr.Parse:1: function \"somethingthatdoesntexist\" not defined",
			expPublicClusterAddress: "",
		},
		{
			name: "unix listener",
			inputConfig: &Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{
						{Address: "someaddr", Type: "unix", Purpose: []string{"cluster"}},
					},
				},
				Controller: &Controller{},
			},
			expPublicClusterAddress: "someaddr:9201",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.stateFn != nil {
				tt.stateFn(t)
			}
			err := tt.inputConfig.SetupControllerPublicClusterAddress(tt.inputFlagValue)
			if tt.expErr {
				require.EqualError(t, err, tt.expErrStr)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, tt.inputConfig.Controller)
			require.Equal(t, tt.expPublicClusterAddress, tt.inputConfig.Controller.PublicClusterAddr)
		})
	}
}

func TestSetupWorkerInitialUpstreams(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name                string
		inputConfig         *Config
		stateFn             func(t *testing.T)
		expErr              bool
		expErrStr           string
		expInitialUpstreams []string
	}{
		{
			name: "NilController",
			inputConfig: &Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Controller: nil,
				Worker: &Worker{
					InitialUpstreams: []string{"192.168.0.2:9201"},
				},
			},
			expErr:              false,
			expErrStr:           "",
			expInitialUpstreams: []string{"192.168.0.2:9201"},
		},
		{
			name: "NilWorker",
			inputConfig: &Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Controller: &Controller{
					PublicClusterAddr: "192.168.0.3:9201",
				},
				Worker: nil,
			},
			expErr:              false,
			expErrStr:           "",
			expInitialUpstreams: nil,
		},
		{
			name: "ipv4 PublicClusterAddr",
			inputConfig: &Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Controller: &Controller{
					PublicClusterAddr: "192.168.0.4:9201",
				},
				Worker: &Worker{},
			},
			expErr:              false,
			expErrStr:           "",
			expInitialUpstreams: []string{"192.168.0.4:9201"},
		},
		{
			name: "ipv6 PublicClusterAddr",
			inputConfig: &Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Controller: &Controller{
					PublicClusterAddr: "[2001:4860:4860:0:0:0:0:8888]:9201",
				},
				Worker: &Worker{},
			},
			expErr:              false,
			expErrStr:           "",
			expInitialUpstreams: []string{"[2001:4860:4860:0:0:0:0:8888]:9201"},
		},
		{
			name: "abbreviated ipv6 PublicClusterAddr",
			inputConfig: &Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Controller: &Controller{
					PublicClusterAddr: "[2001:4860:4860::8888]:9201",
				},
				Worker: &Worker{},
			},
			expErr:              false,
			expErrStr:           "",
			expInitialUpstreams: []string{"[2001:4860:4860::8888]:9201"},
		},
		{
			name: "ListenerNoAddr",
			inputConfig: &Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{
						{
							Purpose: []string{"cluster"},
						},
					},
				},
				Controller: &Controller{},
				Worker:     &Worker{},
			},
			expErr:              false,
			expErrStr:           "",
			expInitialUpstreams: []string{"127.0.0.1:9201"},
		},
		{
			name: "ipv4 ListenerAddr",
			inputConfig: &Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{
						{
							Purpose: []string{"cluster"},
							Address: "192.168.0.5:9201",
						},
					},
				},
				Controller: &Controller{},
				Worker:     &Worker{},
			},
			expErr:              false,
			expErrStr:           "",
			expInitialUpstreams: []string{"192.168.0.5:9201"},
		},
		{
			name: "ipv6 ListenerAddr",
			inputConfig: &Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{
						{
							Purpose: []string{"cluster"},
							Address: "[2001:4860:4860:0:0:0:0:8888]:9201",
						},
					},
				},
				Controller: &Controller{},
				Worker:     &Worker{},
			},
			expErr:              false,
			expErrStr:           "",
			expInitialUpstreams: []string{"[2001:4860:4860:0:0:0:0:8888]:9201"},
		},
		{
			name: "abbreviated ipv6 ListenerAddr",
			inputConfig: &Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{
						{
							Purpose: []string{"cluster"},
							Address: "[2001:4860:4860::8888]:9201",
						},
					},
				},
				Controller: &Controller{},
				Worker:     &Worker{},
			},
			expErr:              false,
			expErrStr:           "",
			expInitialUpstreams: []string{"[2001:4860:4860::8888]:9201"},
		},
		{
			name: "ListenerAddrDomain",
			inputConfig: &Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{
						{
							Purpose: []string{"cluster"},
							Address: "foo.test",
						},
					},
				},
				Controller: &Controller{},
				Worker:     &Worker{},
			},
			expErr:              false,
			expErrStr:           "",
			expInitialUpstreams: []string{"foo.test"},
		},
		{
			name: "ListenerAddrMultiplePurpose",
			inputConfig: &Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{
						{
							Purpose: []string{"cluster", "api"},
						},
					},
				},
				Controller: &Controller{},
				Worker:     &Worker{},
			},
			expErr:              true,
			expErrStr:           "Specifying a listener with more than one purpose is not supported",
			expInitialUpstreams: nil,
		},
		{
			name: "ListenerAddrNoPurposes",
			inputConfig: &Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{
						{
							Purpose: []string{},
						},
					},
				},
				Controller: &Controller{},
				Worker:     &Worker{},
			},
			expErr:              true,
			expErrStr:           "Listener specified without a purpose",
			expInitialUpstreams: nil,
		},
		{
			name: "ListenerAddrMismatchAddress",
			inputConfig: &Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{
						{
							Purpose: []string{"cluster"},
							Address: "192.168.0.5:9201",
						},
					},
				},
				Controller: &Controller{},
				Worker: &Worker{
					InitialUpstreams: []string{"192.168.0.2:9201"},
				},
			},
			expErr:              true,
			expErrStr:           `When running a combined controller and worker, it's invalid to specify a "initial_upstreams" or "controllers" key in the worker block with any values other than the controller cluster or upstream worker address/port when using IPs rather than DNS names`,
			expInitialUpstreams: nil,
		},
		{
			name: "ClusterAddrMismatchAddress",
			inputConfig: &Config{
				SharedConfig: &configutil.SharedConfig{
					Listeners: []*listenerutil.ListenerConfig{},
				},
				Controller: &Controller{
					PublicClusterAddr: "192.168.0.3:9201",
				},
				Worker: &Worker{
					InitialUpstreams: []string{"192.168.0.2:9201"},
				},
			},
			expErr:              true,
			expErrStr:           `When running a combined controller and worker, it's invalid to specify a "initial_upstreams" or "controllers" key in the worker block with any values other than the controller cluster or upstream worker address/port when using IPs rather than DNS names`,
			expInitialUpstreams: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.stateFn != nil {
				tt.stateFn(t)
			}
			err := tt.inputConfig.SetupWorkerInitialUpstreams()
			if tt.expErr {
				require.EqualError(t, err, tt.expErrStr)
				return
			}

			require.NoError(t, err)
			if tt.inputConfig.Worker == nil {
				require.Empty(t, tt.expInitialUpstreams)
			} else {
				require.ElementsMatch(t, tt.expInitialUpstreams, tt.inputConfig.Worker.InitialUpstreams)
			}
		})
	}
}

func TestGetDownstreamWorkersTimeout(t *testing.T) {
	tests := []struct {
		name                  string
		in                    string
		wantController        bool
		wantWorker            bool
		wantControllerTimeout time.Duration
		wantWorkerTimeout     time.Duration
		assertErr             func(*testing.T, error)
	}{
		{
			name: "controller_valid_time_value",
			in: `
			controller {
				name = "example-controller"
				get_downstream_workers_timeout = "10s"
			}`,
			wantControllerTimeout: 10 * time.Second,
			wantWorkerTimeout:     0,
			wantController:        true,
			wantWorker:            false,
			assertErr:             nil,
		},
		{
			name: "worker_valid_time_value",
			in: `
			worker {
				name = "example-worker"
				get_downstream_workers_timeout = "5s"
			}`,
			wantControllerTimeout: 0,
			wantWorkerTimeout:     5 * time.Second,
			wantController:        false,
			wantWorker:            true,
			assertErr:             nil,
		},
		{
			name: "both_valid_time_value",
			in: `
			controller {
				name = "example-controller"
				get_downstream_workers_timeout = "5s"
			}
			worker {
				name = "example-worker"
				get_downstream_workers_timeout = "500ms"
			}`,
			wantControllerTimeout: 5 * time.Second,
			wantWorkerTimeout:     500 * time.Millisecond,
			wantController:        true,
			wantWorker:            true,
			assertErr:             nil,
		},
		{
			name: "both_unspecified_defaults_to_zero",
			in: `
			controller {
				name = "example-controller"
			}
			worker {
				name = "example-worker"
			}`,
			wantController:        true,
			wantWorker:            true,
			wantControllerTimeout: 0,
			wantWorkerTimeout:     0,
			assertErr:             nil,
		},
		{
			name: "controller_int_value_no_unit_assumes_seconds",
			in: `
			controller {
				name = "example-controller"
				get_downstream_workers_timeout = 100
			}`,
			wantController:        true,
			wantWorker:            false,
			wantControllerTimeout: 100 * time.Second,
			wantWorkerTimeout:     0,
		},
		{
			name: "worker_int_value_no_unit_assumes_seconds",
			in: `
			worker {
				name = "example-worker"
				get_downstream_workers_timeout = 30
			}`,
			wantController:    false,
			wantWorker:        true,
			wantWorkerTimeout: 30 * time.Second,
		},
		{
			name: "controller_invalid_bool_value",
			in: `
			controller {
				name = "example-controller"
				get_downstream_workers_timeout = true
			}`,
			wantController: true,
			wantWorker:     false,
			assertErr: func(t *testing.T, err error) {
				require.Error(t, err)
				require.ErrorContains(t, err, `error trying to parse controller get_downstream_workers_timeout`)
			},
		},
		{
			name: "worker_invalid_bool_value",
			in: `
			worker {
				name = "example-worker"
				get_downstream_workers_timeout = false
			}`,
			wantController: false,
			wantWorker:     true,
			assertErr: func(t *testing.T, err error) {
				require.Error(t, err)
				require.ErrorContains(t, err, `error trying to parse worker get_downstream_workers_timeout`)
			},
		},
		{
			name: "controller_invalid_empty_value",
			in: `
			controller {
				name = "example-controller"
				get_downstream_workers_timeout = ""
			}`,
			wantController:        true,
			wantWorker:            false,
			wantControllerTimeout: 0,
		},
		{
			name: "worker_invalid_empty_value",
			in: `
			worker {
				name = "example-worker"
				get_downstream_workers_timeout = ""
			}`,
			wantController:    false,
			wantWorker:        true,
			wantWorkerTimeout: 0,
		},
		{
			name: "controller_invalid_zero_value",
			in: `
			controller {
				name = "example-controller"
				get_downstream_workers_timeout = "0s"
			}`,
			wantController:        true,
			wantWorker:            false,
			wantControllerTimeout: 0,
		},
		{
			name: "worker_invalid_zero_value",
			in: `
			worker {
				name = "example-worker"
				get_downstream_workers_timeout = "0s"
			}`,
			wantController:    false,
			wantWorker:        true,
			wantWorkerTimeout: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := Parse(tt.in)
			if tt.assertErr != nil {
				tt.assertErr(t, err)
				return
			}
			require.NoError(t, err)
			if tt.wantController {
				require.NotNil(t, c.Controller)
				require.Equal(t, tt.wantControllerTimeout, c.Controller.GetDownstreamWorkersTimeoutDuration)
			}
			if tt.wantWorker {
				require.NotNil(t, c.Worker)
				require.Equal(t, tt.wantWorkerTimeout, c.Worker.GetDownstreamWorkersTimeoutDuration)
			}
		})
	}
}

func TestMaxPageSize(t *testing.T) {
	tests := []struct {
		name           string
		in             string
		envMaxPageSize string
		expMaxPageSize uint
		expErr         bool
		expErrStr      string
	}{
		{
			name: "Valid integer value",
			in: `
			controller {
				name = "example-controller"
				max_page_size = 5
			}`,
			expMaxPageSize: 5,
			expErr:         false,
		},
		{
			name: "Valid string value",
			in: `
			controller {
				name = "example-controller"
				max_page_size = "5"
			}`,
			expMaxPageSize: 5,
			expErr:         false,
		},
		{
			name: "Invalid value integer",
			in: `
			controller {
				name = "example-controller"
				max_page_size = 0
			}`,
			expErr:    true,
			expErrStr: "Max page size value must be at least 1, was 0",
		},
		{
			name: "Invalid value string",
			in: `
			controller {
				name = "example-controller"
				max_page_size = "string bad"
			}`,
			expErr: true,
			expErrStr: "Max page size value is not an int: " +
				"strconv.Atoi: parsing \"string bad\": invalid syntax",
		},
		{
			name: "Invalid value type",
			in: `
			controller {
				name = "example-controller"
				max_page_size = false
			}`,
			expErr:    true,
			expErrStr: "Max page size: unsupported type \"bool\"",
		},
		{
			name: "Valid env var",
			in: `
			controller {
				name = "example-controller"
				max_page_size = "env://ENV_MAX_PAGE_SIZE"
			}`,
			expMaxPageSize: 8,
			envMaxPageSize: "8",
			expErr:         false,
		},
		{
			name: "Invalid env var",
			in: `
			controller {
				name = "example-controller"
				max_page_size = "env://ENV_MAX_PAGE_SIZE"
			}`,
			envMaxPageSize: "bogus value",
			expErr:         true,
			expErrStr: "Max page size value is not an int: " +
				"strconv.Atoi: parsing \"bogus value\": invalid syntax",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("ENV_MAX_PAGE_SIZE", tt.envMaxPageSize)
			c, err := Parse(tt.in)
			if tt.expErr {
				require.EqualError(t, err, tt.expErrStr)
				require.Nil(t, c)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, c)
			require.NotNil(t, c.Controller)
			require.Equal(t, tt.expMaxPageSize, c.Controller.MaxPageSize)
		})
	}
}

func TestConcurrentPasswordHashWorkers(t *testing.T) {
	tests := []struct {
		name                             string
		in                               string
		envConcurrentPasswordHashWorkers string
		expConcurrentPasswordHashWorkers uint
		expErr                           bool
		expErrStr                        string
	}{
		{
			name: "Valid integer value",
			in: `
			controller {
				name = "example-controller"
				concurrent_password_hash_workers = 5
			}`,
			expConcurrentPasswordHashWorkers: 5,
			expErr:                           false,
		},
		{
			name: "Valid string value",
			in: `
			controller {
				name = "example-controller"
				concurrent_password_hash_workers = "5"
			}`,
			expConcurrentPasswordHashWorkers: 5,
			expErr:                           false,
		},
		{
			name: "Invalid value integer",
			in: `
			controller {
				name = "example-controller"
				concurrent_password_hash_workers = 0
			}`,
			expErr:    true,
			expErrStr: "Concurrent password hash workers value must be at least 1, was 0",
		},
		{
			name: "Invalid value string",
			in: `
			controller {
				name = "example-controller"
				concurrent_password_hash_workers = "string bad"
			}`,
			expErr: true,
			expErrStr: "Concurrent password hash workers value is not an int: " +
				"strconv.Atoi: parsing \"string bad\": invalid syntax",
		},
		{
			name: "Invalid value string integer",
			in: `
			controller {
				name = "example-controller"
				concurrent_password_hash_workers = "-1"
			}`,
			expErr:    true,
			expErrStr: "Concurrent password hash workers value must be at least 1, was -1",
		},
		{
			name: "Invalid value type",
			in: `
			controller {
				name = "example-controller"
				concurrent_password_hash_workers = false
			}`,
			expErr:    true,
			expErrStr: "Concurrent password hash workers: unsupported type \"bool\"",
		},
		{
			name: "Valid env var",
			in: `
			controller {
				name = "example-controller"
				concurrent_password_hash_workers = "env://ENV_MAX_PW_WORKERS"
			}`,
			expConcurrentPasswordHashWorkers: 8,
			envConcurrentPasswordHashWorkers: "8",
			expErr:                           false,
		},
		{
			name: "Invalid env var",
			in: `
			controller {
				name = "example-controller"
				concurrent_password_hash_workers = "env://ENV_MAX_PW_WORKERS"
			}`,
			envConcurrentPasswordHashWorkers: "bogus value",
			expErr:                           true,
			expErrStr: "Concurrent password hash workers value is not an int: " +
				"strconv.Atoi: parsing \"bogus value\": invalid syntax",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("ENV_MAX_PW_WORKERS", tt.envConcurrentPasswordHashWorkers)
			c, err := Parse(tt.in)
			if tt.expErr {
				require.EqualError(t, err, tt.expErrStr)
				require.Nil(t, c)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, c)
			require.NotNil(t, c.Controller)
			require.Equal(t, tt.expConcurrentPasswordHashWorkers, c.Controller.ConcurrentPasswordHashWorkers)
		})
	}

	t.Run("using environment variable", func(t *testing.T) {
		t.Setenv("BOUNDARY_CONTROLLER_CONCURRENT_PASSWORD_HASH_WORKERS", "2")
		in := `
			controller {
				name = "example-controller"
			}`
		c, err := Parse(in)
		require.NoError(t, err)
		require.NotNil(t, c)
		require.NotNil(t, c.Controller)
		require.EqualValues(t, 2, c.Controller.ConcurrentPasswordHashWorkers)
	})

	t.Run("using environment variable with invalid value", func(t *testing.T) {
		t.Setenv("BOUNDARY_CONTROLLER_CONCURRENT_PASSWORD_HASH_WORKERS", "invalid")
		in := `
			controller {
				name = "example-controller"
			}`
		c, err := Parse(in)
		require.Error(t, err)
		require.Nil(t, c)
		require.Contains(t, err.Error(), "BOUNDARY_CONTROLLER_CONCURRENT_PASSWORD_HASH_WORKERS value is not an int")
	})

	t.Run("using environment variable and config value uses config value", func(t *testing.T) {
		t.Setenv("BOUNDARY_CONTROLLER_CONCURRENT_PASSWORD_HASH_WORKERS", "2")
		in := `
			controller {
				name = "example-controller"
				concurrent_password_hash_workers = 3
			}`
		c, err := Parse(in)
		require.NoError(t, err)
		require.NotNil(t, c)
		require.NotNil(t, c.Controller)
		require.EqualValues(t, 3, c.Controller.ConcurrentPasswordHashWorkers)
	})
}
