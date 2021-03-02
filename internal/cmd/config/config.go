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
	"time"

	"github.com/hashicorp/boundary/sdk/strutil"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/hcl"
	"github.com/hashicorp/shared-secure-libs/configutil"
	"github.com/hashicorp/vault/sdk/helper/parseutil"
	"github.com/mitchellh/mapstructure"
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
	cors_enabled = true
	cors_allowed_origins = ["*"]
}

listener "tcp" {
	purpose = "cluster"
}
`

	devWorkerExtraConfig = `
listener "tcp" {
	purpose = "proxy"
}

worker {
	name = "dev-worker"
	description = "A default worker created in dev mode"
	controllers = ["127.0.0.1"]
	tags {
		type = ["dev", "local"]
	}
}
`
)

// Config is the configuration for the boundary controller
type Config struct {
	*configutil.SharedConfig `hcl:"-"`

	Worker     *Worker     `hcl:"worker"`
	Controller *Controller `hcl:"controller"`

	// Dev-related options
	DevController        bool   `hcl:"-"`
	PassthroughDirectory string `hcl:"-"`
	DevControllerKey     string `hcl:"-"`
	DevWorkerAuthKey     string `hcl:"-"`
	DevRecoveryKey       string `hcl:"-"`
}

type Controller struct {
	Name              string    `hcl:"name"`
	Description       string    `hcl:"description"`
	Database          *Database `hcl:"database"`
	PublicClusterAddr string    `hcl:"public_cluster_addr"`

	// AuthTokenTimeToLive is the total valid lifetime of a token denoted by time.Duration
	AuthTokenTimeToLive         interface{} `hcl:"auth_token_time_to_live"`
	AuthTokenTimeToLiveDuration time.Duration

	// AuthTokenTimeToStale is the total time a token can go unused before becoming invalid
	// denoted by time.Duration
	AuthTokenTimeToStale         interface{} `hcl:"auth_token_time_to_stale"`
	AuthTokenTimeToStaleDuration time.Duration
}

type Worker struct {
	Name        string   `hcl:"name"`
	Description string   `hcl:"description"`
	Controllers []string `hcl:"controllers"`
	PublicAddr  string   `hcl:"public_addr"`

	// We use a raw interface for parsing so that people can use JSON-like
	// syntax that maps directly to the filter input or possibly more familiar
	// key=value syntax. This is trued up in the Parse function below.
	TagsRaw interface{}         `hcl:"tags"`
	Tags    map[string][]string `hcl:"-"`
}

type Database struct {
	Url          string `hcl:"url"`
	MigrationUrl string `hcl:"migration_url"`
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

func DevKeyGeneration() (string, string, string) {
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
	controllerKey, workerAuthKey, recoveryKey := DevKeyGeneration()

	hclStr := fmt.Sprintf(devConfig+devControllerExtraConfig, controllerKey, workerAuthKey, recoveryKey)
	parsed, err := Parse(hclStr)
	if err != nil {
		return nil, fmt.Errorf("error parsing dev config: %w", err)
	}
	parsed.DevController = true
	parsed.DevControllerKey = controllerKey
	parsed.DevWorkerAuthKey = workerAuthKey
	parsed.DevRecoveryKey = recoveryKey
	return parsed, nil
}

func DevCombined() (*Config, error) {
	controllerKey, workerAuthKey, recoveryKey := DevKeyGeneration()
	hclStr := fmt.Sprintf(devConfig+devControllerExtraConfig+devWorkerExtraConfig, controllerKey, workerAuthKey, recoveryKey)
	parsed, err := Parse(hclStr)
	if err != nil {
		return nil, fmt.Errorf("error parsing dev config: %w", err)
	}
	parsed.DevController = true
	parsed.DevControllerKey = controllerKey
	parsed.DevWorkerAuthKey = workerAuthKey
	parsed.DevRecoveryKey = recoveryKey
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

	// Perform controller configuration overrides for auth token settings
	if result.Controller != nil {
		if result.Controller.Name != strings.ToLower(result.Controller.Name) {
			return nil, errors.New("Controller name must be all lower-case")
		}
		if !strutil.Printable(result.Controller.Name) {
			return nil, errors.New("Controller name contains non-printable characters")
		}
		if result.Controller.AuthTokenTimeToLive != "" {
			t, err := parseutil.ParseDurationSecond(result.Controller.AuthTokenTimeToLive)
			if err != nil {
				return result, err
			}
			result.Controller.AuthTokenTimeToLiveDuration = t
		}

		if result.Controller.AuthTokenTimeToStale != "" {
			t, err := parseutil.ParseDurationSecond(result.Controller.AuthTokenTimeToStale)
			if err != nil {
				return result, err
			}
			result.Controller.AuthTokenTimeToStaleDuration = t
		}
	}

	// Parse worker tags
	if result.Worker != nil {
		if result.Worker.Name != strings.ToLower(result.Worker.Name) {
			return nil, errors.New("Worker name must be all lower-case")
		}
		if !strutil.Printable(result.Worker.Name) {
			return nil, errors.New("Worker name contains non-printable characters")
		}
		if result.Worker.TagsRaw != nil {
			switch t := result.Worker.TagsRaw.(type) {
			// HCL allows multiple labeled blocks with the same name, turning it
			// into a slice of maps, hence the slice here. This format is the
			// one that ends up matching the JSON that we use in the expression.
			case []map[string]interface{}:
				if err := mapstructure.WeakDecode(t, &result.Worker.Tags); err != nil {
					return nil, fmt.Errorf("Error decoding the worker's %q section: %w", "tags", err)
				}

			// However for those that are used to other systems, we also accept
			// key=value pairs
			case []interface{}:
				var strs []string
				if err := mapstructure.WeakDecode(t, &strs); err != nil {
					return nil, fmt.Errorf("Error decoding the worker's %q section: %w", "tags", err)
				}
				result.Worker.Tags = make(map[string][]string, len(strs))
				// Aggregate the values by key. We care about the first equal
				// sign only, to allow equals to be in values if needed. This
				// also means we don't support equal signs in keys.
				for _, str := range strs {
					splitStr := strings.SplitN(str, "=", 2)
					switch len(splitStr) {
					case 1:
						return nil, fmt.Errorf("Error decoding tag %q from string: must be in key = value format", str)
					case 2:
						key := splitStr[0]
						v := result.Worker.Tags[key]
						if len(v) == 0 {
							v = make([]string, 0, 1)
						}
						result.Worker.Tags[key] = append(v, splitStr[1])
					}
				}
			}
		}
		for k, v := range result.Worker.Tags {
			if k != strings.ToLower(k) {
				return nil, fmt.Errorf("Tag key %q is not all lower-case letters", k)
			}
			if !strutil.Printable(k) {
				return nil, fmt.Errorf("Tag key %q contains non-printable characters", k)
			}
			for _, val := range v {
				if val != strings.ToLower(val) {
					return nil, fmt.Errorf("Tag value %q for tag key %q is not all lower-case letters", val, k)
				}
				if !strutil.Printable(k) {
					return nil, fmt.Errorf("Tag value %q for tag key %q contains non-printable characters", v, k)
				}
			}
		}
	}

	sharedConfig, err := configutil.ParseConfig(d)
	if err != nil {
		return nil, err
	}
	result.SharedConfig = sharedConfig

	// If cors wasn't specified, enable default values
	for _, listener := range result.SharedConfig.Listeners {
		if strutil.StrListContains(listener.Purpose, "api") {
			if listener.CorsEnabled == nil {
				listener.CorsEnabled = new(bool)
				*listener.CorsEnabled = true
				listener.CorsAllowedOrigins = []string{"serve://boundary"}
			}
		}
	}

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
		return strings.TrimSpace(string(contents)), nil
	case "env":
		return strings.TrimSpace(os.Getenv(strings.TrimPrefix(addr, "env://"))), nil
	}

	return addr, nil
}
