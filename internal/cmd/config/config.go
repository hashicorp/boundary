package config

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/url"
	"os"
	"strings"

	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/hcl"
	"github.com/hashicorp/shared-secure-libs/configutil"
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
controller {
	name = "dev-controller"
	description = "A default controller created in dev mode"
}

kms "aead" {
	purpose = "root"
	aead_type = "aes-gcm"
	key = "%s"
	key_id = "global_root"
}

kms "aead" {
	purpose = "worker-auth"
	aead_type = "aes-gcm"
	key = "%s"
	key_id = "global_worker-auth"
}

kms "aead" {
	purpose = "recovery"
	aead_type = "aes-gcm"
	key = "%s"
	key_id = "global_recovery"
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
	purpose = "proxy"
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

	DevController        bool        `hcl:"-"`
	PassthroughDirectory string      `hcl:"-"`
	Worker               *Worker     `hcl:"worker"`
	Controller           *Controller `hcl:"controller"`
	Database             *Database   `hcl:"database"`
}

type Controller struct {
	Name             string `hcl:"name"`
	Description      string `hcl:"description"`
	DevControllerKey string `hcl:"-"`
	DevWorkerAuthKey string `hcl:"-"`
	DevRecoveryKey   string `hcl:"-"`
}

type Worker struct {
	Name        string   `hcl:"name"`
	Description string   `hcl:"description"`
	Controllers []string `hcl:"controllers"`
}

type Database struct {
	Url string `hcl:"url"`
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

func devKeyGeneration() (string, string, string) {
	var numBytes int64 = 96
	randBuf := new(bytes.Buffer)
	n, err := randBuf.ReadFrom(&io.LimitedReader{
		R: rand.Reader,
		N: numBytes,
	})
	if err != nil {
		panic(err)
	}
	if n != numBytes {
		panic(fmt.Errorf("expected to read 64 bytes, read %d", n))
	}
	controllerKey := base64.StdEncoding.EncodeToString(randBuf.Bytes()[0:32])
	workerAuthKey := base64.StdEncoding.EncodeToString(randBuf.Bytes()[32:64])
	recoveryKey := base64.StdEncoding.EncodeToString(randBuf.Bytes()[64:numBytes])

	return controllerKey, workerAuthKey, recoveryKey
}

// DevController is a Config that is used for dev mode of Boundary
// controllers
func DevController() (*Config, error) {
	controllerKey, workerAuthKey, recoveryKey := devKeyGeneration()

	hclStr := fmt.Sprintf(devConfig+devControllerExtraConfig, controllerKey, workerAuthKey, recoveryKey)
	parsed, err := Parse(hclStr)
	if err != nil {
		return nil, fmt.Errorf("error parsing dev config: %w", err)
	}
	parsed.DevController = true
	parsed.Controller.DevControllerKey = controllerKey
	parsed.Controller.DevWorkerAuthKey = workerAuthKey
	parsed.Controller.DevRecoveryKey = recoveryKey
	return parsed, nil
}

func DevCombined() (*Config, error) {
	controllerKey, workerAuthKey, recoveryKey := devKeyGeneration()
	hclStr := fmt.Sprintf(devConfig+devControllerExtraConfig+devWorkerExtraConfig, controllerKey, workerAuthKey, recoveryKey)
	parsed, err := Parse(hclStr)
	if err != nil {
		return nil, fmt.Errorf("error parsing dev config: %w", err)
	}
	parsed.DevController = true
	parsed.Controller.DevControllerKey = controllerKey
	parsed.Controller.DevWorkerAuthKey = workerAuthKey
	parsed.Controller.DevRecoveryKey = recoveryKey
	return parsed, nil
}

func New() *Config {
	return &Config{
		SharedConfig: new(configutil.SharedConfig),
	}
}

// LoadFile loads the configuration from the given file.
func LoadFile(path string, wrapper wrapping.Wrapper) (*Config, error) {
	d, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	raw := string(d)

	if wrapper != nil {
		raw, err = configutil.EncryptDecrypt(raw, true, true, wrapper)
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

var ErrNotAUrl = errors.New("not a url")

// ParseAddress parses a URL with schemes file://, env://, or any other.
// Depending on the scheme it will return specific types of data:
//
// * file:// will return a string with the file's contents * env:// will return
// a string with the env var's contents * anything else will return the string
// as it was
//
// On error, we return the original string along with the error. The caller can
// switch on ErrNotAUrl to understand whether it was the parsing step that
// errored or something else. This is useful to attempt to read a non-URL string
// from some resource, but where the original input may simply be a valid string
// of that type.
func ParseAddress(addr string) (string, error) {
	addr = strings.TrimSpace(addr)
	parsed, err := url.Parse(addr)
	if err != nil {
		return addr, ErrNotAUrl
	}
	switch parsed.Scheme {
	case "file":
		contents, err := ioutil.ReadFile(strings.TrimPrefix(addr, "file://"))
		if err != nil {
			return addr, fmt.Errorf("error reading file at %s: %w", addr, err)
		}
		return string(contents), nil
	case "env":
		return os.Getenv(strings.TrimPrefix(addr, "env://")), nil
	}

	return addr, nil
}
