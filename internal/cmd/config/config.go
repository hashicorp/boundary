package config

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"strings"
	"time"

	"github.com/hashicorp/boundary/internal/observability/event"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-secure-stdlib/base62"
	"github.com/hashicorp/go-secure-stdlib/configutil"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
	"github.com/mitchellh/mapstructure"
)

const (
	desktopCorsOrigin = "serve://boundary"

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
	DevController       bool   `hcl:"-"`
	DevUiPassthroughDir string `hcl:"-"`
	DevControllerKey    string `hcl:"-"`
	DevWorkerAuthKey    string `hcl:"-"`
	DevRecoveryKey      string `hcl:"-"`

	// Eventing configuration for the controller
	Eventing *event.EventerConfig `hcl:"events"`

	// Plugin-related options
	Plugins Plugins `hcl:"plugins"`
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

	// StatusGracePeriod represents the period of time (as a duration) that the
	// controller will wait before marking connections from a disconnected worker
	// as invalid.
	//
	// TODO: This field is currently internal.
	StatusGracePeriodDuration time.Duration `hcl:"-"`

	// SchedulerRunJobInterval is the time interval between waking up the
	// scheduler to run pending jobs.
	//
	// TODO: This field is currently internal.
	SchedulerRunJobInterval time.Duration `hcl:"-"`
}

func (c *Controller) InitNameIfEmpty() (string, error) {
	if c == nil {
		return "", fmt.Errorf("controller config is empty")
	}
	if err := initNameIfEmpty(&c.Name); err != nil {
		return "", fmt.Errorf("error auto-generating controller name: %w", err)
	}
	return c.Name, nil
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

	// StatusGracePeriod represents the period of time (as a duration) that the
	// worker will wait before disconnecting connections if it cannot make a
	// status report to a controller.
	//
	// TODO: This field is currently internal.
	StatusGracePeriodDuration time.Duration `hcl:"-"`
}

func (w *Worker) InitNameIfEmpty() (string, error) {
	if w == nil {
		return "", fmt.Errorf("worker config is empty")
	}
	if err := initNameIfEmpty(&w.Name); err != nil {
		return "", fmt.Errorf("error auto-generating worker name: %w", err)
	}
	return w.Name, nil
}

func initNameIfEmpty(name *string) error {
	if *name == "" {
		var err error
		if *name, err = base62.Random(10); err != nil {
			return err
		}
	}
	return nil
}

type Database struct {
	Url                string `hcl:"url"`
	MigrationUrl       string `hcl:"migration_url"`
	MaxOpenConnections int    `hcl:"max_open_connections"`
}

type Plugins struct {
	ExecutionDir string `hcl:"execution_dir"`
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

	result := New()
	if err := hcl.DecodeObject(result, obj); err != nil {
		return nil, err
	}

	// Perform controller configuration overrides for auth token settings
	if result.Controller != nil {
		result.Controller.Name, err = parsePath(result.Controller.Name)
		if err != nil {
			return nil, fmt.Errorf("Error parsing controller name: %w", err)
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
		result.Worker.Name, err = parsePath(result.Worker.Name)
		if err != nil {
			return nil, fmt.Errorf("Error parsing worker name: %w", err)
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

	for _, listener := range result.SharedConfig.Listeners {
		if strutil.StrListContains(listener.Purpose, "api") &&
			(listener.CorsDisableDefaultAllowedOriginValues == nil || !*listener.CorsDisableDefaultAllowedOriginValues) {
			switch listener.CorsEnabled {
			case nil:
				// If CORS wasn't specified, enable default value of *, which allows
				// both the admin UI (without the user having to explicitly set an
				// origin) and the desktop origin
				listener.CorsEnabled = new(bool)
				*listener.CorsEnabled = true
				listener.CorsAllowedOrigins = []string{"*"}

			default:
				// If not the wildcard and they haven't disabled us auto-adding
				// origin values, add the desktop client origin
				if *listener.CorsEnabled &&
					!strutil.StrListContains(listener.CorsAllowedOrigins, "*") {
					listener.CorsAllowedOrigins = strutil.AppendIfMissing(listener.CorsAllowedOrigins, desktopCorsOrigin)
				}
			}
		}
	}

	list, ok := obj.Node.(*ast.ObjectList)
	if !ok {
		return nil, fmt.Errorf("error parsing: file doesn't contain a root object")
	}

	eventList := list.Filter("events")
	switch len(eventList.Items) {
	case 0:
		result.Eventing = event.DefaultEventerConfig()
	case 1:
		if result.Eventing, err = parseEventing(eventList.Items[0]); err != nil {
			return nil, fmt.Errorf(`error parsing "events": %w`, err)
		}
	default:
		return nil, fmt.Errorf(`too many "events" nodes (max 1, got %d)`, len(eventList.Items))
	}

	return result, nil
}

func parsePath(urlField string) (string, error) {
	// input is returned in error states to preserve `parseutil.ParsePath` functionality.
	field, err := parseutil.ParsePath(urlField)
	if err != nil && !errors.Is(err, parseutil.ErrNotAUrl) {
		return urlField, err
	}
	if field != strings.ToLower(field) {
		return urlField, errors.New("field must be all lower-case")
	}
	if !strutil.Printable(field) {
		return urlField, errors.New("field contains non-printable characters")
	}

	return field, nil
}

func parseEventing(eventObj *ast.ObjectItem) (*event.EventerConfig, error) {
	// Decode the outside struct
	var result event.EventerConfig
	if err := hcl.DecodeObject(&result, eventObj.Val); err != nil {
		return nil, fmt.Errorf(`error decoding "events" node: %w`, err)
	}
	// Now, find the sinks
	eventObjType, ok := eventObj.Val.(*ast.ObjectType)
	if !ok {
		return nil, fmt.Errorf(`error interpreting "events" node as an object type`)
	}
	list := eventObjType.List
	sinkList := list.Filter("sink")
	// Go through each sink and decode
	for i, item := range sinkList.Items {
		var s event.SinkConfig
		if err := hcl.DecodeObject(&s, item.Val); err != nil {
			return nil, fmt.Errorf("error decoding eventer sink entry %d", i)
		}

		// Fix up type and validate
		switch {
		case s.Type != "":
		case len(item.Keys) == 1:
			s.Type = event.SinkType(item.Keys[0].Token.Value().(string))
		default:
			switch {
			case s.StderrConfig != nil:
				// If we haven't found the type any other way, they _must_
				// specify this block even though there are no config parameters
				s.Type = event.StderrSink
			case s.FileConfig != nil:
				s.Type = event.FileSink
			default:
				return nil, fmt.Errorf("sink type could not be determined")
			}
		}
		s.Type = event.SinkType(strings.ToLower(string(s.Type)))

		if s.Type == event.StderrSink && s.StderrConfig == nil {
			// StderrConfig is optional as it has no values, but ensure it's
			// always populated if it's the type
			s.StderrConfig = new(event.StderrSinkTypeConfig)
		}

		// parse the duration string specified in a file config into a time.Duration
		if s.FileConfig != nil && s.FileConfig.RotateDurationHCL != "" {
			var err error
			s.FileConfig.RotateDuration, err = parseutil.ParseDurationSecond(s.FileConfig.RotateDurationHCL)
			if err != nil {
				return nil, fmt.Errorf("can't parse rotation duration %s", s.FileConfig.RotateDurationHCL)
			}
		}

		if err := s.Validate(); err != nil {
			return nil, err
		}

		// Append to result
		result.Sinks = append(result.Sinks, &s)
	}
	if len(result.Sinks) == 0 {
		result.Sinks = []*event.SinkConfig{event.DefaultSink()}
	}
	return &result, nil
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
