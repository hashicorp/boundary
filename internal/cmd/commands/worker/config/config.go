package config

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/hashicorp/hcl"
	"github.com/hashicorp/vault/internalshared/configutil"
)

// Config is the configuration for the watchtower controller
type Config struct {
	*configutil.SharedConfig `hcl:"-"`
}

// Dev is a Config that is used for dev mode of Watchtower
func Dev() (*Config, error) {
	randBuf := new(bytes.Buffer)
	n, err := randBuf.ReadFrom(&io.LimitedReader{
		R: rand.Reader,
		N: 64,
	})
	if err != nil {
		return nil, err
	}
	if n != 64 {
		return nil, fmt.Errorf("expected to read 64 bytes, read %d", n)
	}
	controllerKey := base64.StdEncoding.EncodeToString(randBuf.Bytes()[0:32])
	workerAuthKey := base64.StdEncoding.EncodeToString(randBuf.Bytes()[32:64])

	hclStr := `
disable_mlock = true

listener "tcp" {
	tls_disable = true
	proxy_protocol_behavior = "allow_authorized"
	proxy_protocol_authorized_addrs = "127.0.0.1"
}

telemetry {
	prometheus_retention_time = "24h"
	disable_hostname = true
}
`

	hclStr = fmt.Sprintf(hclStr, controllerKey, workerAuthKey)
	parsed, err := Parse(hclStr)
	if err != nil {
		return nil, fmt.Errorf("error parsing dev config: %w", err)
	}
	return parsed, nil
}

func New() *Config {
	return &Config{
		SharedConfig: new(configutil.SharedConfig),
	}
}

// LoadFile loads the configuration from the given file.
func LoadFile(path string) (*Config, error) {
	// Read the file
	d, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	conf, err := Parse(string(d))
	if err != nil {
		return nil, err
	}

	return conf, nil
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
