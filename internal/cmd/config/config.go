package config

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/hashicorp/hcl"
	"github.com/hashicorp/vault/internalshared/configutil"
)

const (
	devConfig = `
disable_mlock = true

telemetry {
	prometheus_retention_time = "24h"
	disable_hostname = true
}
`

	devControllerExtraConfig = `
kms "aead" {
	purpose = "controller"
	aead_type = "aes-gcm"
	key = "%s"
}

kms "aead" {
	purpose = "worker-auth"
	aead_type = "aes-gcm"
	key = "%s"
}

listener "tcp" {
	purpose = "api"
	tls_disable = true
	proxy_protocol_behavior = "allow_authorized"
	proxy_protocol_authorized_addrs = "127.0.0.1"
	cors_enabled = true
	cors_allowed_origins = ["*"]
}

listener "tcp" {
	purpose = "cluster"
	tls_disable = true
	proxy_protocol_behavior = "allow_authorized"
	proxy_protocol_authorized_addrs = "127.0.0.1"
}
`

	devWorkerExtraConfig = `
listener "tcp" {
	purpose = "worker-alpn-tls"
	tls_disable = true
	proxy_protocol_behavior = "allow_authorized"
	proxy_protocol_authorized_addrs = "127.0.0.1"
}

worker {
	name = "dev-worker"
	description = "A default worker created in dev mode"
	controllers = ["127.0.0.1"]
}
`
)

// Config is the configuration for the boundary controller
type Config struct {
	*configutil.SharedConfig `hcl:"-"`

	DevController        bool    `hcl:"-"`
	DefaultOrgId         string  `hcl:"default_org_id"`
	PassthroughDirectory string  `hcl:"-"`
	Worker               *Worker `hcl:"worker"`
}

type Worker struct {
	Name        string   `hcl:"name"`
	Description string   `hcl:"description"`
	Controllers []string `hcl:"controllers"`
}

// DevWorker is a Config that is used for dev mode of Boundary
// workers
func DevWorker() (*Config, error) {
	parsed, err := Parse(devConfig + devWorkerExtraConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing dev config: %w", err)
	}
	return parsed, nil
}

func devKeyGeneration() (string, string) {
	randBuf := new(bytes.Buffer)
	n, err := randBuf.ReadFrom(&io.LimitedReader{
		R: rand.Reader,
		N: 64,
	})
	if err != nil {
		panic(err)
	}
	if n != 64 {
		panic(fmt.Errorf("expected to read 64 bytes, read %d", n))
	}
	controllerKey := base64.StdEncoding.EncodeToString(randBuf.Bytes()[0:32])
	workerAuthKey := base64.StdEncoding.EncodeToString(randBuf.Bytes()[32:64])
	return controllerKey, workerAuthKey
}

// DevController is a Config that is used for dev mode of Boundary
// controllers
func DevController() (*Config, error) {
	controllerKey, workerAuthKey := devKeyGeneration()

	hclStr := fmt.Sprintf(devConfig+devControllerExtraConfig, controllerKey, workerAuthKey)
	parsed, err := Parse(hclStr)
	if err != nil {
		return nil, fmt.Errorf("error parsing dev config: %w", err)
	}
	parsed.DevController = true
	return parsed, nil
}

func DevCombined() (*Config, error) {
	controllerKey, workerAuthKey := devKeyGeneration()
	hclStr := fmt.Sprintf(devConfig+devControllerExtraConfig+devWorkerExtraConfig, controllerKey, workerAuthKey)
	parsed, err := Parse(hclStr)
	if err != nil {
		return nil, fmt.Errorf("error parsing dev config: %w", err)
	}
	parsed.DevController = true
	return parsed, nil
}

func New() *Config {
	return &Config{
		SharedConfig: new(configutil.SharedConfig),
	}
}

// LoadFile loads the configuration from the given file.
func LoadFile(path string, kms *configutil.KMS) (*Config, error) {
	d, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	raw := string(d)

	if kms != nil {
		raw, err = configDecrypt(raw, kms)
		if err != nil {
			return nil, err
		}
	}

	return Parse(raw)
}

func Parse(d string) (*Config, error) {
	obj, err := hcl.Parse(d)
	if err != nil {
		return nil, err
	}

	// Nothing to do here right now
	result := New()
	if err := hcl.DecodeObject(result, obj); err != nil {
		return nil, err
	}

	sharedConfig, err := configutil.ParseConfig(d)
	if err != nil {
		return nil, err
	}
	result.SharedConfig = sharedConfig

	return result, nil
}

// Sanitized returns a copy of the config with all values that are considered
// sensitive stripped. It also strips all `*Raw` values that are mainly
// used for parsing.
//
// Specifically, the fields that this method strips are:
// - KMS.Config
// - Telemetry.CirconusAPIToken
func (c *Config) Sanitized() map[string]interface{} {
	// Create shared config if it doesn't exist (e.g. in tests) so that map
	// keys are actually populated
	if c.SharedConfig == nil {
		c.SharedConfig = new(configutil.SharedConfig)
	}
	sharedResult := c.SharedConfig.Sanitized()
	result := map[string]interface{}{}
	for k, v := range sharedResult {
		result[k] = v
	}

	return result
}

func configDecrypt(raw string, kms *configutil.KMS) (string, error) {
	wrapper, err := configutil.ConfigureWrapper(kms, nil, nil, nil)
	if err != nil {
		return raw, err
	}

	wrapper.Init(context.Background())
	defer wrapper.Finalize(context.Background())

	return configutil.EncryptDecrypt(raw, true, true, wrapper)
}
