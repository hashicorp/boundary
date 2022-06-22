package config

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/observability/event"
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
	exp := &Config{
		Eventing: event.DefaultEventerConfig(),
		SharedConfig: &configutil.SharedConfig{
			DisableMlock: true,
			Listeners: []*listenerutil.ListenerConfig{
				{
					Type:               "tcp",
					Purpose:            []string{"api"},
					TLSDisable:         true,
					CorsEnabled:        truePointer,
					CorsAllowedOrigins: []string{"*"},
				},
				{
					Type:    "tcp",
					Purpose: []string{"cluster"},
				},
				{
					Type:       "tcp",
					Purpose:    []string{"ops"},
					TLSDisable: true,
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
					Purpose: []string{"worker-auth-storage"},
					Config: map[string]string{
						"aead_type": "aes-gcm",
						"key_id":    "global_worker-auth-storage",
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
			Name:        "dev-controller",
			Description: "A default controller created in dev mode",
		},
		DevController: true,
	}

	exp.Listeners[0].RawConfig = actual.Listeners[0].RawConfig
	exp.Listeners[1].RawConfig = actual.Listeners[1].RawConfig
	exp.Listeners[2].RawConfig = actual.Listeners[2].RawConfig
	exp.Seals[0].Config["key"] = actual.Seals[0].Config["key"]
	exp.Seals[1].Config["key"] = actual.Seals[1].Config["key"]
	exp.Seals[2].Config["key"] = actual.Seals[2].Config["key"]
	exp.Seals[3].Config["key"] = actual.Seals[3].Config["key"]
	exp.DevControllerKey = actual.Seals[0].Config["key"]
	exp.DevWorkerAuthKey = actual.Seals[1].Config["key"]
	exp.DevWorkerAuthStorageKey = actual.Seals[2].Config["key"]
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
	actual, err := DevWorker()
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
				},
			},
		},
		Worker: &Worker{
			Name:                "w_1234567890",
			Description:         "A default worker created in dev mode",
			InitialUpstreams:    []string{"127.0.0.1"},
			InitialUpstreamsRaw: []interface{}{"127.0.0.1"},
			Tags: map[string][]string{
				"type": {"dev", "local"},
			},
		},
	}

	exp.Listeners[0].RawConfig = actual.Listeners[0].RawConfig
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
}

func TestDevCombined(t *testing.T) {
	actual, err := DevCombined()
	if err != nil {
		t.Fatal(err)
	}

	truePointer := new(bool)
	*truePointer = true
	exp := &Config{
		Eventing: event.DefaultEventerConfig(),
		SharedConfig: &configutil.SharedConfig{
			DisableMlock: true,
			Listeners: []*listenerutil.ListenerConfig{
				{
					Type:               "tcp",
					Purpose:            []string{"api"},
					TLSDisable:         true,
					CorsEnabled:        truePointer,
					CorsAllowedOrigins: []string{"*"},
				},
				{
					Type:    "tcp",
					Purpose: []string{"cluster"},
				},
				{
					Type:       "tcp",
					Purpose:    []string{"ops"},
					TLSDisable: true,
				},
				{
					Type:    "tcp",
					Purpose: []string{"proxy"},
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
					Purpose: []string{"worker-auth-storage"},
					Config: map[string]string{
						"aead_type": "aes-gcm",
						"key_id":    "global_worker-auth-storage",
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
			Name:        "dev-controller",
			Description: "A default controller created in dev mode",
		},
		DevController: true,
		Worker: &Worker{
			Name:                "w_1234567890",
			Description:         "A default worker created in dev mode",
			InitialUpstreams:    []string{"127.0.0.1"},
			InitialUpstreamsRaw: []interface{}{"127.0.0.1"},
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
	exp.DevControllerKey = actual.Seals[0].Config["key"]
	exp.DevWorkerAuthKey = actual.Seals[1].Config["key"]
	exp.DevWorkerAuthStorageKey = actual.Seals[2].Config["key"]
	exp.DevRecoveryKey = actual.Seals[3].Config["key"]
	exp.Worker.TagsRaw = actual.Worker.TagsRaw
	assert.Equal(t, exp, actual)
}

func TestDevWorkerCredentialStorageDir(t *testing.T) {
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

func TestDevKeyGeneration(t *testing.T) {
	t.Parallel()
	dk := DevKeyGeneration()
	numBytes := 32
	require.Equal(t, numBytes, len(dk))
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
			expErrStr:     "Error unmarshalling env var/file contents: json: cannot unmarshal object into Go value of type []string",
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
			name: "One Upstream",
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
			name: "Unsupported object",
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
			expErrStr:          "Failed to parse worker upstreams: unexpected type \"[]map[string]interface {}\"",
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
		{
			name: "Worker using deprecated controllers field",
			in: `
			worker {
				name = "test"
				controllers = ["127.0.0.1", "127.0.0.2", "127.0.0.3"]
			}`,
			expWorkerUpstreams: []string{"127.0.0.1", "127.0.0.2", "127.0.0.3"},
			expErr:             false,
		},
		{
			name: "Different values in controllers and initial_upstreams field",
			in: `
			worker {
				name = "test"
				controllers = ["127.0.0.1", "127.0.0.2", "127.0.0.3"]
				initial_upstreams = ["127.0.0.1"]
			}`,
			expWorkerUpstreams: nil,
			expErr:             true,
			expErrStr:          "Failed to parse worker upstreams: both initial_upstreams and controllers fields are populated",
		},
		{
			name: "Identical values in controllers and initial_upstreams field",
			in: `
			worker {
				name = "test"
				controllers = ["127.0.0.1"]
				initial_upstreams = ["127.0.0.1"]
			}`,
			expWorkerUpstreams: nil,
			expErr:             true,
			expErrStr:          "Failed to parse worker upstreams: both initial_upstreams and controllers fields are populated",
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
