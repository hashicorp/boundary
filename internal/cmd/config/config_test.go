package config

import (
	"testing"
	"time"

	"github.com/hashicorp/shared-secure-libs/configutil"
	"github.com/stretchr/testify/assert"
)

func TestDevController(t *testing.T) {
	actual, err := DevController()
	if err != nil {
		t.Fatal(err)
	}

	exp := &Config{
		SharedConfig: &configutil.SharedConfig{
			DisableMlock: true,
			Listeners: []*configutil.Listener{
				{
					Type:               "tcp",
					Purpose:            []string{"api"},
					TLSDisable:         true,
					CorsEnabled:        true,
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
			Telemetry: &configutil.Telemetry{
				DisableHostname:         true,
				PrometheusRetentionTime: 24 * time.Hour,
				UsageGaugePeriod:        10 * time.Minute,
				MaximumGaugeCardinality: 500,
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
}

func TestDevWorker(t *testing.T) {
	actual, err := DevWorker()
	if err != nil {
		t.Fatal(err)
	}

	exp := &Config{
		SharedConfig: &configutil.SharedConfig{
			DisableMlock: true,
			Listeners: []*configutil.Listener{
				{
					Type:    "tcp",
					Purpose: []string{"proxy"},
				},
			},
			Telemetry: &configutil.Telemetry{
				DisableHostname:         true,
				PrometheusRetentionTime: 24 * time.Hour,
				UsageGaugePeriod:        10 * time.Minute,
				MaximumGaugeCardinality: 500,
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
