package config

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/go-secure-stdlib/configutil"
	"github.com/hashicorp/go-secure-stdlib/listenerutil"
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
	exp.Seals[0].Config["key"] = actual.Seals[0].Config["key"]
	exp.Seals[1].Config["key"] = actual.Seals[1].Config["key"]
	exp.Seals[2].Config["key"] = actual.Seals[2].Config["key"]
	exp.DevControllerKey = actual.Seals[0].Config["key"]
	exp.DevWorkerAuthKey = actual.Seals[1].Config["key"]
	exp.DevRecoveryKey = actual.Seals[2].Config["key"]

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
			Name:        "dev-worker",
			Description: "A default worker created in dev mode",
			Controllers: []string{"127.0.0.1"},
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
		name = "dev-worker"
		description = "A default worker created in dev mode"
		controllers = ["127.0.0.1"]
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
		name = "dev-worker"
		description = "A default worker created in dev mode"
		controllers = ["127.0.0.1"]
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
		name = "dev-worker"
		description = "A default worker created in dev mode"
		controllers = ["127.0.0.1"]
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
			name = "dev-worker"
			description = "A default worker created in dev mode"
			controllers = ["127.0.0.1"]
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
		controllers = ["127.0.0.1"]
		tags = ["type=dev", "type=local"]
	}
	`

	_, err = Parse(devConfig + devWorkerKeyValueConfig)
	assert.Error(t, err)
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
			templateWorker:     "barfoo",
			expectedController: "foobar",
			expectedWorker:     "barfoo",
		},
		{
			name:               "env",
			templateController: fmt.Sprintf("env://%s", controllerEnv),
			templateWorker:     fmt.Sprintf("env://%s", workerEnv),
			envController:      "foobar2",
			envWorker:          "barfoo2",
			expectedController: "foobar2",
			expectedWorker:     "barfoo2",
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

func TestParsingPath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		in        string
		expOut    string
		expErrStr string
	}{
		{
			name:      "env: not present",
			in:        "env://TEST_ENV_FIELD_THAT_SURELY_DOESNT_EXIST",
			expOut:    "",
			expErrStr: "",
		},
		{
			name:      "file: not present",
			in:        "file://test_file_that_surely_doesnt_exist",
			expOut:    "file://test_file_that_surely_doesnt_exist",
			expErrStr: "error reading file at file://test_file_that_surely_doesnt_exist: open test_file_that_surely_doesnt_exist: no such file or directory",
		},
		{
			name:      "not a url",
			in:        "some-value",
			expOut:    "some-value",
			expErrStr: "",
		},
		{
			name:      "upper case value",
			in:        "some-VALUE",
			expOut:    "some-VALUE",
			expErrStr: "field must be all lower-case",
		},
		{
			name:      "non-printable value",
			in:        "some-val\u0000ue",
			expOut:    "some-val\u0000ue",
			expErrStr: "field contains non-printable characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := parsePath(tt.in)
			if len(tt.expErrStr) > 0 {
				require.EqualError(t, err, tt.expErrStr)
				require.Equal(t, tt.in, out)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.expOut, out)
		})
	}
}
