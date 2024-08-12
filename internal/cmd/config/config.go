// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/boundary/internal/ratelimit"
	"github.com/hashicorp/boundary/internal/storage"
	"github.com/hashicorp/boundary/internal/util"
	kms_plugin_assets "github.com/hashicorp/boundary/plugins/kms"
	"github.com/hashicorp/boundary/sdk/wrapper"
	"github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	configutil "github.com/hashicorp/go-secure-stdlib/configutil/v2"
	"github.com/hashicorp/go-secure-stdlib/listenerutil"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/go-secure-stdlib/pluginutil/v2"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
	"github.com/mitchellh/mapstructure"
)

var extraParsingFuncs []func(*Config) error

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
	purpose = "bsr"
	aead_type = "aes-gcm"
	key = "%s"
	key_id = "global_bsr"
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

listener "tcp" {
	purpose = "ops"
	tls_disable = true
}
`

	devWorkerExtraConfig = `
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

kms "aead" {
    purpose = "worker-auth-storage"
	aead_type = "aes-gcm"
	key = "%s"
	key_id = "worker-auth-storage"
}
`

	// We use a custom Content-Security-Policy because we need to add wasm-unsafe-eval
	// as a script-src to support asciinema playback on the Admin UI. Users can still
	// override this value via the configuration.
	defaultCsp = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; frame-src 'self'; font-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self'; media-src 'self'; manifest-src 'self'; style-src-attr 'self'; frame-ancestors 'self'"
)

// Config is the configuration for the boundary controller
type Config struct {
	*configutil.SharedConfig `hcl:"-"`

	Worker     *Worker     `hcl:"worker"`
	Controller *Controller `hcl:"controller"`

	// Dev-related options
	DevController           bool   `hcl:"-"`
	DevUiPassthroughDir     string `hcl:"-"`
	DevControllerKey        string `hcl:"-"`
	DevWorkerAuthKey        string `hcl:"-"`
	DevWorkerAuthStorageKey string `hcl:"-"`
	DevBsrKey               string `hcl:"-"`
	DevRecoveryKey          string `hcl:"-"`

	// Eventing configuration for the controller
	Eventing *event.EventerConfig `hcl:"events"`

	// Plugin-related options
	Plugins Plugins `hcl:"plugins"`

	// Internal field for use with HCP deployments. Used if controllers/
	// initial_upstreams is not set.
	HcpbClusterId string `hcl:"hcp_boundary_cluster_id"`

	// Whether to log information from the worker authentication process. This
	// shouldn't divulge any secrets but may contain information considered
	// sensitive. This should only be enabled for debugging purposes, and can be
	// toggled with SIGHUP.
	EnableWorkerAuthDebugging bool `hcl:"enable_worker_auth_debugging"`

	// For opting out of license utilization reporting
	Reporting Reporting `hcl:"reporting"`
}

type Controller struct {
	Name              string    `hcl:"name"`
	Description       string    `hcl:"description"`
	Database          *Database `hcl:"database"`
	PublicClusterAddr string    `hcl:"public_cluster_addr"`
	Scheduler         Scheduler `hcl:"scheduler"`

	// AuthTokenTimeToLive is the total valid lifetime of a token denoted by time.Duration
	AuthTokenTimeToLive         any           `hcl:"auth_token_time_to_live"`
	AuthTokenTimeToLiveDuration time.Duration `hcl:"-"`

	// AuthTokenTimeToStale is the total time a token can go unused before becoming invalid
	// denoted by time.Duration
	AuthTokenTimeToStale         any           `hcl:"auth_token_time_to_stale"`
	AuthTokenTimeToStaleDuration time.Duration `hcl:"-"`

	// GracefulShutdownWait is the amount of time that we'll wait before actually
	// starting the Controller shutdown. This allows the health endpoint to
	// return a status code to indicate that the instance is shutting down.
	GracefulShutdownWait         any           `hcl:"graceful_shutdown_wait_duration"`
	GracefulShutdownWaitDuration time.Duration `hcl:"-"`

	// WorkerStatusGracePeriod represents the period of time (as a duration)
	// that the controller will wait before deciding a worker is disconnected
	// and marking connections from it as canceling
	//
	// TODO: This isn't documented (on purpose) because the right place for this
	// is central configuration so you can't drift across controllers, but we
	// don't have that yet.
	WorkerStatusGracePeriod         any           `hcl:"worker_status_grace_period"`
	WorkerStatusGracePeriodDuration time.Duration `hcl:"-"`

	// LivenessTimeToStale represents the period of time (as a duration) after
	// which it will consider other controllers to be no longer accessible,
	// based on time since their last status update in the database
	//
	// TODO: This isn't documented (on purpose) because the right place for this
	// is central configuration so you can't drift across controllers, but we
	// don't have that yet.
	LivenessTimeToStale         any           `hcl:"liveness_time_to_stale"`
	LivenessTimeToStaleDuration time.Duration `hcl:"-"`

	// TODO: This isn't documented (on purpose) because the right place for this
	// is central configuration so you can't drift across controllers and workers
	// but we don't have that yet.
	GetDownstreamWorkersTimeout         any           `hcl:"get_downstream_workers_timeout"`
	GetDownstreamWorkersTimeoutDuration time.Duration `hcl:"-"`

	// SchedulerRunJobInterval is the time interval between waking up the
	// scheduler to run pending jobs.
	//
	// TODO: This field is currently internal.
	SchedulerRunJobInterval time.Duration `hcl:"-"`

	ApiRateLimits           ratelimit.Configs `hcl:"-"`
	ApiRateLimiterMaxQuotas int               `hcl:"api_rate_limit_max_quotas"`
	ApiRateLimitDisable     bool              `hcl:"api_rate_limit_disable"`

	// License is the license used by HCP builds
	License string `hcl:"license"`

	// MaxPageSize overrides the default and max page size.
	// The default page size is what is used when the page size
	// is not explicitly provided by the user. The max page size
	// is the greatest number the page size can be set to before
	// it is rejected by the controller.
	MaxPageSizeRaw any  `hcl:"max_page_size"`
	MaxPageSize    uint `hcl:"-"`
}

func (c *Controller) InitNameIfEmpty(ctx context.Context) error {
	if c == nil {
		return fmt.Errorf("controller config is empty")
	}
	if c.Name != "" {
		return nil
	}

	var err error
	c.Name, err = db.NewPublicId(ctx, "c")
	if err != nil {
		return fmt.Errorf("error auto-generating controller name: %w", err)
	}

	return nil
}

type Worker struct {
	Name        string `hcl:"name"`
	Description string `hcl:"description"`
	PublicAddr  string `hcl:"public_addr"`

	// We use a raw interface here so that we can take in a string
	// value pointing to an env var or file. We then resolve that
	// and get the actual upstream controller or worker addresses.
	InitialUpstreams    []string `hcl:"-"`
	InitialUpstreamsRaw any      `hcl:"initial_upstreams"`

	// The ControllersRaw field is deprecated and users should use InitialUpstreamsRaw instead.
	// TODO: remove this field when support is discontinued.
	ControllersRaw any `hcl:"controllers"`

	// We use a raw interface for parsing so that people can use JSON-like
	// syntax that maps directly to the filter input or possibly more familiar
	// key=value syntax, as well as accepting a string denoting an env or file
	// pointer. This is trued up in the Parse function below.
	Tags    map[string][]string `hcl:"-"`
	TagsRaw any                 `hcl:"tags"`

	// StatusCallTimeout represents the period of time (as a duration) that
	// the worker will allow a status RPC call to attempt to finish before
	// canceling it to try again.
	//
	// TODO: This is currently not documented and considered internal.
	StatusCallTimeout         any           `hcl:"status_call_timeout"`
	StatusCallTimeoutDuration time.Duration `hcl:"-"`

	// GetDownstreamWorkersTimeout represents the period of time (as a duration) timeout
	// for GetDownstreamWorkers call in DownstreamWorkerTicker
	//
	// TODO: This is currently not documented and considered internal.
	GetDownstreamWorkersTimeout         any           `hcl:"get_downstream_workers_timeout"`
	GetDownstreamWorkersTimeoutDuration time.Duration `hcl:"-"`

	// SuccessfulStatusGracePeriod represents the period of time (as a duration)
	// that the worker will wait before disconnecting connections if it cannot
	// successfully complete a status report to a controller. This cannot be
	// less than StatusCallTimeout.
	//
	// TODO: This is currently not documented and considered internal.
	SuccessfulStatusGracePeriod         any           `hcl:"successful_status_grace_period"`
	SuccessfulStatusGracePeriodDuration time.Duration `hcl:"-"`

	// AuthStoragePath represents the location a worker stores its node credentials, if set
	AuthStoragePath string `hcl:"auth_storage_path"`

	// RecordingStoragePath represents the location a worker caches session recordings before
	// they are sync'ed to the corresponding storage bucket. The path must already exist.
	RecordingStoragePath string `hcl:"recording_storage_path"`

	// RecordingStorageMinimumAvailableCapacity represents the minimum amount of available
	// disk space a worker needs in the path defined by RecordingStoragePath for processing
	// sessions with recording enabled. The expected input value for this field is a
	// “capacity string“. Supported suffixes are kb, kib, mb, mib, gb, gib, tb, tib, which
	// are not case sensitive. We use a raw interface for parsing so that users can input a
	// "capacity string" which is converted into a uint64 value that is measured in bytes.
	RecordingStorageMinimumAvailableCapacity  any    `hcl:"recording_storage_minimum_available_capacity"`
	RecordingStorageMinimumAvailableDiskSpace uint64 `hcl:"-"`

	// ControllerGeneratedActivationToken is a controller-generated activation
	// token used to register this worker to the cluster. It can be a path, env
	// var, or direct value.
	ControllerGeneratedActivationToken string `hcl:"controller_generated_activation_token"`

	// UseDeprecatedKmsAuthMethod indicates that the worker should use the
	// pre-0.13 method of using KMSes to authenticate. This is currently only
	// supported to throw an error if used telling people they need to upgrade.
	UseDeprecatedKmsAuthMethod bool `hcl:"use_deprecated_kms_auth_method"`
}

type Database struct {
	Url                     string         `hcl:"url"`
	MigrationUrl            string         `hcl:"migration_url"`
	MaxOpenConnections      int            `hcl:"-"`
	MaxOpenConnectionsRaw   any            `hcl:"max_open_connections"`
	MaxIdleConnections      *int           `hcl:"-"`
	MaxIdleConnectionsRaw   any            `hcl:"max_idle_connections"`
	ConnMaxIdleTime         any            `hcl:"max_idle_time"`
	ConnMaxIdleTimeDuration *time.Duration `hcl:"-"`

	// SkipSharedLockAcquisition allows skipping grabbing the database shared
	// lock. This is dangerous unless you know what you're doing, and you should
	// not set it unless you are the reason it's here in the first place, as not
	// only it dangerous but it will be removed at some point in the future.
	SkipSharedLockAcquisition bool `hcl:"skip_shared_lock_acquisition"`
}

// Scheduler is the configuration block that specifies the job scheduler behavior on the controller
type Scheduler struct {
	// JobRunInterval is the time interval between waking up the
	// scheduler to run pending jobs.
	//
	JobRunInterval         any `hcl:"job_run_interval"`
	JobRunIntervalDuration time.Duration

	// MonitorInterval is the time interval between waking up the
	// scheduler to monitor for jobs that are defunct.
	//
	MonitorInterval         any `hcl:"monitor_interval"`
	MonitorIntervalDuration time.Duration
}

type Plugins struct {
	ExecutionDir string `hcl:"execution_dir"`
}

type Reporting struct {
	License License `hcl:"license"`
}

type License struct {
	Enabled bool `hcl:"enabled"`
}

// DevWorker is a Config that is used for dev mode of Boundary
// workers. Supported options: WithObservationsEnabled, WithSysEventsEnabled,
// WithAuditEventsEnabled, TestWithErrorEventsEnabled
func DevWorker(opt ...Option) (*Config, error) {
	workerAuthStorageKey := DevKeyGeneration()
	hclStr := fmt.Sprintf(devConfig+devWorkerExtraConfig, workerAuthStorageKey)
	parsed, err := Parse(hclStr)
	if err != nil {
		return nil, fmt.Errorf("error parsing dev config: %w", err)
	}
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("error parsing options: %w", err)
	}
	parsed.Eventing.AuditEnabled = opts.withAuditEventsEnabled
	parsed.Eventing.ObservationsEnabled = opts.withObservationsEnabled
	parsed.Eventing.SysEventsEnabled = opts.withSysEventsEnabled
	parsed.Eventing.ErrorEventsDisabled = !opts.testWithErrorEventsEnabled
	return parsed, nil
}

func DevKeyGeneration() string {
	var numBytes int64 = 32
	randBuf := new(bytes.Buffer)
	n, err := randBuf.ReadFrom(&io.LimitedReader{
		R: rand.Reader,
		N: numBytes,
	})
	if err != nil {
		panic(err)
	}
	if n != numBytes {
		panic(fmt.Errorf("expected to read 32 bytes, read %d", n))
	}
	devKey := base64.StdEncoding.EncodeToString(randBuf.Bytes())
	return devKey
}

// DevController is a Config that is used for dev mode of Boundary
// controllers
func DevController(opt ...Option) (*Config, error) {
	controllerKey := DevKeyGeneration()
	workerAuthKey := DevKeyGeneration()
	bsrKey := DevKeyGeneration()
	recoveryKey := DevKeyGeneration()

	hclStr := fmt.Sprintf(devConfig+devControllerExtraConfig, controllerKey, workerAuthKey, bsrKey, recoveryKey)
	parsed, err := Parse(hclStr)
	if err != nil {
		return nil, fmt.Errorf("error parsing dev config: %w", err)
	}
	parsed.DevController = true
	parsed.DevControllerKey = controllerKey
	parsed.DevWorkerAuthKey = workerAuthKey
	parsed.DevBsrKey = bsrKey
	parsed.DevRecoveryKey = recoveryKey
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("error parsing options: %w", err)
	}
	parsed.Eventing.AuditEnabled = opts.withAuditEventsEnabled
	parsed.Eventing.ObservationsEnabled = opts.withObservationsEnabled
	parsed.Eventing.SysEventsEnabled = opts.withSysEventsEnabled
	parsed.Eventing.ErrorEventsDisabled = !opts.testWithErrorEventsEnabled
	return parsed, nil
}

func DevCombined() (*Config, error) {
	controllerKey := DevKeyGeneration()
	workerAuthKey := DevKeyGeneration()
	workerAuthStorageKey := DevKeyGeneration()
	bsrKey := DevKeyGeneration()
	recoveryKey := DevKeyGeneration()
	hclStr := fmt.Sprintf(devConfig+devControllerExtraConfig+devWorkerExtraConfig, controllerKey, workerAuthKey, bsrKey, recoveryKey, workerAuthStorageKey)
	parsed, err := Parse(hclStr)
	if err != nil {
		return nil, fmt.Errorf("error parsing dev config: %w", err)
	}
	parsed.DevController = true
	parsed.DevControllerKey = controllerKey
	parsed.DevWorkerAuthKey = workerAuthKey
	parsed.DevWorkerAuthStorageKey = workerAuthStorageKey
	parsed.DevBsrKey = bsrKey
	parsed.DevRecoveryKey = recoveryKey
	return parsed, nil
}

func New() *Config {
	return &Config{
		SharedConfig: new(configutil.SharedConfig),
	}
}

// Load will create a Config from the given config files. It concatenates the
// contents of the files together. This allows for composing a config from
// separate files, but notably does not attempt any merging of configs. Thus it
// is possible that the concatenation results in an invalid config file. This
// also supports decrypting the config, either with a kms block in one of the
// given files, or as a separate file in wrapperPath.
//
// Note that having multiple config files is only supported properly if they are
// all hcl files. If they are json files, only the first file is used. A mix of
// hcl and json will result in an error.
func Load(ctx context.Context, paths []string, wrapperPath string) (*Config, error) {
	const op = "config.Load"

	var err error
	var cfg *Config

	configStrs := make([]string, 0, len(paths))
	for _, path := range paths {
		fileBytes, err := os.ReadFile(path)
		if err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("could not read config file", "path", path, "error", err))
			return nil, err
		}
		configStrs = append(configStrs, string(fileBytes))
	}
	configString := strings.Join(configStrs, "\n")

	wrapperString := configString
	if wrapperPath != "" {
		wrapperBytes, err := os.ReadFile(wrapperPath)
		if err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("could not read kms config file", "path", wrapperPath, "error", err))
			return nil, err
		}
		wrapperString = string(wrapperBytes)
	}

	var configWrapper wrapping.Wrapper
	var ifWrapper wrapping.InitFinalizer
	var cleanupFunc func() error
	if wrapperString != "" {
		configWrapper, cleanupFunc, err = wrapper.GetWrapperFromHcl(
			ctx,
			wrapperString,
			globals.KmsPurposeConfig,
			configutil.WithPluginOptions(
				pluginutil.WithPluginsMap(kms_plugin_assets.BuiltinKmsPlugins()),
				pluginutil.WithPluginsFilesystem(kms_plugin_assets.KmsPluginPrefix, kms_plugin_assets.FileSystem()),
			),
			// TODO: How would we want to expose this kind of log to users when
			// using recovery configs? Generally with normal CLI commands we
			// don't print out all of these logs. We may want a logger with a
			// custom writer behind our existing gate where we print nothing
			// unless there is an error, then dump all of it.
			configutil.WithLogger(hclog.NewNullLogger()),
		)
		if err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("could not get kms wrapper from config", "path", wrapperPath))
			return nil, err
		}
		if cleanupFunc != nil {
			defer func() {
				if err := cleanupFunc(); err != nil {
					event.WriteError(ctx, op, err, event.WithInfoMsg("could not clean up kms wrapper", "path", wrapperPath))
				}
			}()
		}
		if configWrapper != nil {
			ifWrapper, _ = configWrapper.(wrapping.InitFinalizer)
		}
	}
	if ifWrapper != nil {
		if err := ifWrapper.Init(ctx); err != nil && !errors.Is(err, wrapping.ErrFunctionNotImplemented) {
			event.WriteError(ctx, op, err, event.WithInfoMsg("could not initialize kms", "path", wrapperPath))
			return nil, err
		}
	}

	if configWrapper != nil {
		configString, err = configutil.EncryptDecrypt(configString, true, true, configWrapper)
		if err != nil {
			return nil, err
		}
	}

	cfg, err = Parse(configString)

	if ifWrapper != nil {
		if err := ifWrapper.Finalize(context.Background()); err != nil && !errors.Is(err, wrapping.ErrFunctionNotImplemented) {
			event.WriteError(context.Background(), op, err, event.WithInfoMsg("could not finalize kms", "path", wrapperPath))
			return nil, err
		}
	}
	return cfg, err
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
		result.Controller.Name, err = parseutil.ParsePath(result.Controller.Name)
		if err != nil && !errors.Is(err, parseutil.ErrNotAUrl) {
			return nil, fmt.Errorf("Error parsing controller name: %w", err)
		}
		if result.Controller.Name != strings.ToLower(result.Controller.Name) {
			return nil, errors.New("Controller name must be all lower-case")
		}
		if !strutil.Printable(result.Controller.Name) {
			return nil, errors.New("Controller name contains non-printable characters")
		}
		result.Controller.Description, err = parseutil.ParsePath(result.Controller.Description)
		if err != nil && !errors.Is(err, parseutil.ErrNotAUrl) {
			return nil, fmt.Errorf("Error parsing controller description: %w", err)
		}
		if !strutil.Printable(result.Controller.Description) {
			return nil, errors.New("Controller description contains non-printable characters")
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

		if result.Controller.GracefulShutdownWait != "" {
			t, err := parseutil.ParseDurationSecond(result.Controller.GracefulShutdownWait)
			if err != nil {
				return result, err
			}
			result.Controller.GracefulShutdownWaitDuration = t
		}

		if result.Controller.Scheduler.JobRunInterval != "" {
			t, err := parseutil.ParseDurationSecond(result.Controller.Scheduler.JobRunInterval)
			if err != nil {
				return result, err
			}
			result.Controller.Scheduler.JobRunIntervalDuration = t
		}

		if result.Controller.Scheduler.MonitorInterval != "" {
			t, err := parseutil.ParseDurationSecond(result.Controller.Scheduler.MonitorInterval)
			if err != nil {
				return result, err
			}
			result.Controller.Scheduler.MonitorIntervalDuration = t
		}

		workerStatusGracePeriod := result.Controller.WorkerStatusGracePeriod
		if util.IsNil(workerStatusGracePeriod) {
			workerStatusGracePeriod = os.Getenv("BOUNDARY_CONTROLLER_WORKER_STATUS_GRACE_PERIOD")
		}
		if workerStatusGracePeriod != nil {
			t, err := parseutil.ParseDurationSecond(workerStatusGracePeriod)
			if err != nil {
				return result, err
			}
			result.Controller.WorkerStatusGracePeriodDuration = t
		}
		if result.Controller.WorkerStatusGracePeriodDuration < 0 {
			return nil, errors.New("Controller worker status grace period value is negative")
		}

		livenessTimeToStale := result.Controller.LivenessTimeToStale
		if util.IsNil(livenessTimeToStale) {
			livenessTimeToStale = os.Getenv("BOUNDARY_CONTROLLER_LIVENESS_TIME_TO_STALE")
		}
		if livenessTimeToStale != nil {
			t, err := parseutil.ParseDurationSecond(livenessTimeToStale)
			if err != nil {
				return result, err
			}
			result.Controller.LivenessTimeToStaleDuration = t
		}
		if result.Controller.LivenessTimeToStaleDuration < 0 {
			return nil, errors.New("Controller liveness time to stale value is negative")
		}

		getDownstreamWorkersTimeout := result.Controller.GetDownstreamWorkersTimeout
		if util.IsNil(getDownstreamWorkersTimeout) {
			getDownstreamWorkersTimeout = os.Getenv("BOUNDARY_CONTROLLER_GET_DOWNSTREAM_WORKERS_TIMEOUT")
		}
		if getDownstreamWorkersTimeout != nil {
			t, err := parseutil.ParseDurationSecond(getDownstreamWorkersTimeout)
			if err != nil {
				return result, err
			}
			result.Controller.GetDownstreamWorkersTimeoutDuration = t
		}
		if result.Controller.GetDownstreamWorkersTimeoutDuration < 0 {
			return nil, errors.New("GetDownstreamWorkersTimeoutDuration value is negative")
		}

		if result.Controller.MaxPageSizeRaw != nil {
			switch t := result.Controller.MaxPageSizeRaw.(type) {
			case string:
				maxPageSizeString, err := parseutil.ParsePath(t)
				if err != nil && !errors.Is(err, parseutil.ErrNotAUrl) {
					return nil, fmt.Errorf("Error parsing max page size: %w", err)
				}
				pageSize, err := strconv.Atoi(maxPageSizeString)
				if err != nil {
					return nil, fmt.Errorf("Max page size value is not an int: %w", err)
				}
				if pageSize <= 0 {
					return nil, fmt.Errorf("Max page size value must be at least 1, was %d", pageSize)
				}
				result.Controller.MaxPageSize = uint(pageSize)
			case int:
				if t <= 0 {
					return nil, fmt.Errorf("Max page size value must be at least 1, was %d", t)
				}
				result.Controller.MaxPageSize = uint(t)
			default:
				return nil, fmt.Errorf("Max page size: unsupported type %q", reflect.TypeOf(t).String())
			}
		}

		if result.Controller.Database != nil {
			if result.Controller.Database.MaxOpenConnectionsRaw != nil {
				switch t := result.Controller.Database.MaxOpenConnectionsRaw.(type) {
				case string:
					maxOpenConnectionsString, err := parseutil.ParsePath(t)
					if err != nil && !errors.Is(err, parseutil.ErrNotAUrl) {
						return nil, fmt.Errorf("Error parsing database max open connections: %w", err)
					}
					result.Controller.Database.MaxOpenConnections, err = strconv.Atoi(maxOpenConnectionsString)
					if err != nil {
						return nil, fmt.Errorf("Database max open connections value is not an int: %w", err)
					}
				case int:
					result.Controller.Database.MaxOpenConnections = t
				default:
					return nil, fmt.Errorf("Database max open connections: unsupported type %q",
						reflect.TypeOf(t).String())
				}
			}
			if result.Controller.Database.MaxIdleConnectionsRaw != nil {
				switch t := result.Controller.Database.MaxIdleConnectionsRaw.(type) {
				case string:
					maxIdleConnectionsString, err := parseutil.ParsePath(t)
					if err != nil && !errors.Is(err, parseutil.ErrNotAUrl) {
						return nil, fmt.Errorf("Error parsing database max idle connections: %w", err)
					}
					idleConns, err := strconv.Atoi(maxIdleConnectionsString)
					if err != nil {
						return nil, fmt.Errorf("Database max idle connections value is not a uint: %w", err)
					}
					result.Controller.Database.MaxIdleConnections = &idleConns
				case int:
					result.Controller.Database.MaxIdleConnections = &t
				default:
					return nil, fmt.Errorf("Database max idle connections: unsupported type %q",
						reflect.TypeOf(t).String())
				}
			}
			if result.Controller.Database.ConnMaxIdleTime != nil {
				switch t := result.Controller.Database.ConnMaxIdleTime.(type) {
				case string:
					durationString, err := parseutil.ParsePath(t)
					if err != nil && !errors.Is(err, parseutil.ErrNotAUrl) {
						return nil, fmt.Errorf("Error parsing connection max idle time: %w", err)
					}
					connMaxIdleTime, err := parseutil.ParseDurationSecond(durationString)
					if err != nil {
						return nil, fmt.Errorf("Connection max idle time is not a duration: %w", err)
					}
					result.Controller.Database.ConnMaxIdleTimeDuration = &connMaxIdleTime
				default:
					return nil, fmt.Errorf("Database connection max idle time: unsupported type %q",
						reflect.TypeOf(t).String())
				}
			}
		}

		result.Controller.ApiRateLimits, err = parseApiRateLimits(obj.Node)
		if err != nil {
			return nil, err
		}

		if result.Controller.ApiRateLimiterMaxQuotas <= 0 {
			result.Controller.ApiRateLimiterMaxQuotas = ratelimit.DefaultLimiterMaxQuotas()
		}
	}

	// Parse worker tags
	if result.Worker != nil {
		if result.Worker.UseDeprecatedKmsAuthMethod {
			return nil, fmt.Errorf("The flag 'use_deprecated_auth_method' is unsupported as of version 0.15.")
		}

		result.Worker.Name, err = parseutil.ParsePath(result.Worker.Name)
		if err != nil && !errors.Is(err, parseutil.ErrNotAUrl) {
			return nil, fmt.Errorf("Error parsing worker name: %w", err)
		}
		if result.Worker.Name != strings.ToLower(result.Worker.Name) {
			return nil, errors.New("Worker name must be all lower-case")
		}
		if !strutil.Printable(result.Worker.Name) {
			return nil, errors.New("Worker name contains non-printable characters")
		}

		result.Worker.Description, err = parseutil.ParsePath(result.Worker.Description)
		if err != nil && !errors.Is(err, parseutil.ErrNotAUrl) {
			return nil, fmt.Errorf("Error parsing worker description: %w", err)
		}
		if !strutil.Printable(result.Worker.Description) {
			return nil, errors.New("Worker description contains non-printable characters")
		}

		result.Worker.ControllerGeneratedActivationToken, err = parseutil.ParsePath(result.Worker.ControllerGeneratedActivationToken)
		if err != nil && !errors.Is(err, parseutil.ErrNotAUrl) {
			return nil, fmt.Errorf("Error parsing worker activation token: %w", err)
		}

		statusCallTimeoutDuration := result.Worker.StatusCallTimeout
		if util.IsNil(statusCallTimeoutDuration) {
			statusCallTimeoutDuration = os.Getenv("BOUNDARY_WORKER_STATUS_CALL_TIMEOUT")
		}
		if statusCallTimeoutDuration != nil {
			t, err := parseutil.ParseDurationSecond(statusCallTimeoutDuration)
			if err != nil {
				return result, err
			}
			result.Worker.StatusCallTimeoutDuration = t
		}
		if result.Worker.StatusCallTimeoutDuration < 0 {
			return nil, errors.New("Status call timeout value is negative")
		}

		getDownstreamWorkersTimeoutDuration := result.Worker.GetDownstreamWorkersTimeout
		if util.IsNil(getDownstreamWorkersTimeoutDuration) {
			getDownstreamWorkersTimeoutDuration = os.Getenv("BOUNDARY_WORKER_GET_DOWNSTREAM_WORKERS_TIMEOUT")
		}
		if getDownstreamWorkersTimeoutDuration != nil {
			t, err := parseutil.ParseDurationSecond(getDownstreamWorkersTimeoutDuration)
			if err != nil {
				return result, fmt.Errorf("error parsing get_downstream_worker_call_timeout: %w", err)
			}
			result.Worker.GetDownstreamWorkersTimeoutDuration = t
		}
		if result.Worker.GetDownstreamWorkersTimeoutDuration < 0 {
			return nil, errors.New("GetDownstreamWorkersTimeoutDuration call timeout value is negative")
		}

		successfulStatusGracePeriod := result.Worker.SuccessfulStatusGracePeriod
		if util.IsNil(successfulStatusGracePeriod) {
			successfulStatusGracePeriod = os.Getenv("BOUNDARY_WORKER_SUCCESSFUL_STATUS_GRACE_PERIOD")
		}
		if successfulStatusGracePeriod != nil {
			t, err := parseutil.ParseDurationSecond(successfulStatusGracePeriod)
			if err != nil {
				return result, err
			}
			result.Worker.SuccessfulStatusGracePeriodDuration = t
		}
		if result.Worker.SuccessfulStatusGracePeriodDuration < 0 {
			return nil, errors.New("Successful status grace period value is negative")
		}

		if !util.IsNil(result.Worker.RecordingStorageMinimumAvailableCapacity) {
			if result.Worker.RecordingStoragePath == "" {
				return nil, errors.New("recording_storage_path cannot be empty when providing recording_storage_minimum_available_capacity")
			}
			recordingStorageMinimumAvailableDiskSpace, err := parseutil.ParseCapacityString(result.Worker.RecordingStorageMinimumAvailableCapacity)
			if err != nil {
				return result, err
			}
			result.Worker.RecordingStorageMinimumAvailableDiskSpace = recordingStorageMinimumAvailableDiskSpace
		}
		// RecordingStorageMinimumAvailableDiskSpace defaults to 500MiB when not set by the user
		if result.Worker.RecordingStoragePath != "" && result.Worker.RecordingStorageMinimumAvailableDiskSpace == 0 {
			result.Worker.RecordingStorageMinimumAvailableDiskSpace = storage.DefaultMinimumAvailableDiskSpace
		}

		switch {
		case result.Worker.StatusCallTimeoutDuration == 0 && result.Worker.SuccessfulStatusGracePeriodDuration == 0:
			// Nothing
		case result.Worker.StatusCallTimeoutDuration != 0 && result.Worker.SuccessfulStatusGracePeriodDuration != 0:
			if result.Worker.StatusCallTimeoutDuration > result.Worker.SuccessfulStatusGracePeriodDuration {
				return nil, fmt.Errorf("Worker setting for status call timeout duration must be less than or equal to successful status grace period duration")
			}
		default:
			return nil, fmt.Errorf("Worker settings for status call timeout duration and successful status grace period duration must either both be set or both be empty")
		}

		if result.Worker.TagsRaw != nil {
			switch t := result.Worker.TagsRaw.(type) {
			// We allow `tags` to be a simple string containing a URL with schema.
			// See: https://github.com/hashicorp/go-secure-stdlib/blob/main/parseutil/parsepath.go
			case string:
				rawTags, err := parseutil.ParsePath(t)
				if err != nil {
					return nil, fmt.Errorf("Error parsing worker tags: %w", err)
				}

				var temp []map[string]any
				err = hcl.Decode(&temp, rawTags)
				if err != nil {
					return nil, fmt.Errorf("Error decoding raw worker tags: %w", err)
				}

				if err := mapstructure.WeakDecode(temp, &result.Worker.Tags); err != nil {
					return nil, fmt.Errorf("Error decoding the worker's tags: %w", err)
				}

			// HCL allows multiple labeled blocks with the same name, turning it
			// into a slice of maps, hence the slice here. This format is the
			// one that ends up matching the JSON that we use in the expression.
			case []map[string]any:
				for _, m := range t {
					for k, v := range m {
						// We allow the user to pass in only the keys in HCL, and
						// then set the values to point to a URL with schema.
						valStr, ok := v.(string)
						if !ok {
							continue
						}

						parsed, err := parseutil.ParsePath(valStr)
						if err != nil && !errors.Is(err, parseutil.ErrNotAUrl) {
							return nil, fmt.Errorf("Error parsing worker tag values: %w", err)
						}
						if valStr == parsed {
							// Nothing was found, ignore.
							// WeakDecode will still parse it though as we
							// don't know if this could be a valid tag.
							continue
						}

						var tags []string
						err = json.Unmarshal([]byte(parsed), &tags)
						if err != nil {
							return nil, fmt.Errorf("Error unmarshaling env var/file contents: %w", err)
						}
						m[k] = tags
					}
				}

				if err := mapstructure.WeakDecode(t, &result.Worker.Tags); err != nil {
					return nil, fmt.Errorf("Error decoding the worker's %q section: %w", "tags", err)
				}

			// However for those that are used to other systems, we also accept
			// key=value pairs
			case []any:
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
			if strings.Contains(k, ",") {
				return nil, fmt.Errorf("Tag key %q cannot contain commas", k)
			}
			for _, val := range v {
				if val != strings.ToLower(val) {
					return nil, fmt.Errorf("Tag value %q for tag key %q is not all lower-case letters", val, k)
				}
				if !strutil.Printable(k) {
					return nil, fmt.Errorf("Tag value %q for tag key %q contains non-printable characters", v, k)
				}
				if strings.Contains(val, ",") {
					return nil, fmt.Errorf("Tag value %q for tag key %q cannot contain commas", val, k)
				}
			}
		}

		result.Worker.InitialUpstreams, err = parseWorkerUpstreams(result)
		if err != nil {
			return nil, fmt.Errorf("Failed to parse worker upstreams: %w", err)
		}
	}

	// Now that we can have multiple KMSes for downstream workers, allow an
	// unlimited number of KMS blocks as we don't know how many might be defined
	sharedConfig, err := configutil.ParseConfig(
		d,
		configutil.WithMaxKmsBlocks(-1),
		configutil.WithListenerOptions(listenerutil.WithDefaultUiContentSecurityPolicyHeader(defaultCsp)),
	)
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

	if result.Plugins.ExecutionDir != "" {
		result.Plugins.ExecutionDir, err = parseutil.ParsePath(result.Plugins.ExecutionDir)
		if err != nil && !errors.Is(err, parseutil.ErrNotAUrl) {
			return nil, fmt.Errorf("Error parsing plugins execution dir: %w", err)
		}
	}

	for _, f := range extraParsingFuncs {
		if err := f(result); err != nil {
			return nil, err
		}
	}

	return result, nil
}

// supportControllersRawConfig returns either initialUpstreamsRaw or controllersRaw depending on which is populated. Errors when both fields are populated.
func supportControllersRawConfig(initialUpstreamsRaw, controllersRaw any) (any, error) {
	switch {
	case initialUpstreamsRaw == nil && controllersRaw != nil:
		return controllersRaw, nil
	case initialUpstreamsRaw != nil && controllersRaw != nil:
		return nil, fmt.Errorf("both initial_upstreams and controllers fields are populated")
	}
	return initialUpstreamsRaw, nil
}

func parseApiRateLimits(node ast.Node) (ratelimit.Configs, error) {
	list, ok := node.(*ast.ObjectList)
	if !ok {
		return nil, fmt.Errorf("error parsing: file doesn't contain a root object")
	}
	controllerList := list.Filter("controller")

	configs := make(ratelimit.Configs, 0)
	for _, item := range controllerList.Items {
		controller, ok := item.Val.(*ast.ObjectType)
		if !ok {
			return nil, fmt.Errorf("error parsing: file doesn't contain controller object")
		}
		apiRateLimitsList := controller.List.Filter("api_rate_limit")

		var err error
		for i, item := range apiRateLimitsList.Items {
			var a ratelimit.Config
			if err := hcl.DecodeObject(&a, item.Val); err != nil {
				return nil, fmt.Errorf("error decoding controller api_rate_limit entry %d", i)
			}
			a.Period, err = parseutil.ParseDurationSecond(a.PeriodHCL)
			if err != nil {
				return nil, fmt.Errorf("error decoding controller api_rate_limit period for entry %d", i)
			}
			configs = append(configs, &a)
		}
	}

	return configs, nil
}

func parseWorkerUpstreams(c *Config) ([]string, error) {
	if c == nil || c.Worker == nil {
		return nil, fmt.Errorf("config or worker field is nil")
	}
	if c.Worker.InitialUpstreamsRaw == nil && c.Worker.ControllersRaw == nil {
		// return nil here so that other address sources can be provided outside of config
		return nil, nil
	}
	rawUpstreams, err := supportControllersRawConfig(c.Worker.InitialUpstreamsRaw, c.Worker.ControllersRaw)
	if err != nil {
		return nil, err
	}

	switch t := rawUpstreams.(type) {
	case []any:
		var upstreams []string
		err := mapstructure.WeakDecode(rawUpstreams, &upstreams)
		if err != nil {
			return nil, fmt.Errorf("failed to decode worker initial_upstreams block into config field: %w", err)
		}
		return upstreams, nil

	case string:
		upstreamsStr, err := parseutil.ParsePath(t)
		if err != nil {
			return nil, fmt.Errorf("bad env var or file pointer: %w", err)
		}

		var upstreams []string
		err = json.Unmarshal([]byte(upstreamsStr), &upstreams)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal env/file contents: %w", err)
		}
		return upstreams, nil

	default:
		typ := reflect.TypeOf(t)
		return nil, fmt.Errorf("unexpected type %q", typ.String())
	}
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

		// parse map into event types
		if s.AuditConfig != nil && s.AuditConfig.FilterOverridesHCL != nil {
			s.AuditConfig.FilterOverrides = make(map[event.DataClassification]event.FilterOperation, len(s.AuditConfig.FilterOverridesHCL))
			for k, v := range s.AuditConfig.FilterOverridesHCL {
				s.AuditConfig.FilterOverrides[event.DataClassification(k)] = event.FilterOperation(v)
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
func (c *Config) Sanitized() map[string]any {
	// Create shared config if it doesn't exist (e.g. in tests) so that map
	// keys are actually populated
	if c.SharedConfig == nil {
		c.SharedConfig = new(configutil.SharedConfig)
	}
	sharedResult := c.SharedConfig.Sanitized()
	result := map[string]any{}
	for k, v := range sharedResult {
		result[k] = v
	}

	return result
}

// SetupControllerPublicClusterAddress will set the controller public address.
// If the flagValue is provided it will be used. Otherwise this will use the
// address from cluster listener. In either case it will check to see if no port
// is included, and if not it will set the default port of 9201.
//
// If there are any errors parsing the address from the flag or listener,
// and error is returned.
func (c *Config) SetupControllerPublicClusterAddress(flagValue string) error {
	if c.Controller == nil {
		c.Controller = new(Controller)
	}
	if flagValue != "" {
		c.Controller.PublicClusterAddr = flagValue
	}
	if c.Controller.PublicClusterAddr == "" {
	FindAddr:
		for _, listener := range c.Listeners {
			for _, purpose := range listener.Purpose {
				if purpose == "cluster" {
					c.Controller.PublicClusterAddr = listener.Address
					break FindAddr
				}
			}
		}
	} else {
		var err error
		c.Controller.PublicClusterAddr, err = parseutil.ParsePath(c.Controller.PublicClusterAddr)
		if err != nil && !errors.Is(err, parseutil.ErrNotAUrl) {
			return fmt.Errorf("Error parsing public cluster addr: %w", err)
		}

		c.Controller.PublicClusterAddr, err = listenerutil.ParseSingleIPTemplate(c.Controller.PublicClusterAddr)
		if err != nil {
			return fmt.Errorf("Error parsing IP template on controller public cluster addr: %w", err)
		}
	}

	host, port, err := net.SplitHostPort(c.Controller.PublicClusterAddr)
	if err != nil {
		if strings.Contains(err.Error(), "missing port") {
			port = "9201"
			host = c.Controller.PublicClusterAddr
		} else {
			return fmt.Errorf("Error splitting public cluster adddress host/port: %w", err)
		}
	}
	c.Controller.PublicClusterAddr = net.JoinHostPort(host, port)
	return nil
}

// SetupWorkerInitialUpstreams will set the worker initial upstreams in cases
// where both a worker and controller stanza are provided. The initial upstreams
// will be:
// - The initialily provided value, if it is the same as the controller's cluster address
// - The controller's public cluster address if it it was set
// - The controller's cluster listener's address
//
// Any other value already set for iniital upstream will result in an error.
func (c *Config) SetupWorkerInitialUpstreams() error {
	// nothing to do here
	if c.Worker == nil || c.Controller == nil {
		return nil
	}

	var clusterAddr string
	for _, lnConfig := range c.Listeners {
		switch len(lnConfig.Purpose) {
		case 0:
			return fmt.Errorf("Listener specified without a purpose")
		case 1:
			purpose := lnConfig.Purpose[0]
			switch purpose {
			case "cluster":
				clusterAddr = lnConfig.Address
				if clusterAddr == "" {
					clusterAddr = "127.0.0.1:9201"
					lnConfig.Address = clusterAddr
				}
			}
		default:
			return fmt.Errorf("Specifying a listener with more than one purpose is not supported")
		}
	}

	switch len(c.Worker.InitialUpstreams) {
	case 0:
		if c.Controller.PublicClusterAddr != "" {
			clusterAddr = c.Controller.PublicClusterAddr
		}
		c.Worker.InitialUpstreams = []string{clusterAddr}
	case 1:
		if c.Worker.InitialUpstreams[0] == clusterAddr {
			break
		}
		if c.Controller.PublicClusterAddr != "" &&
			c.Worker.InitialUpstreams[0] == c.Controller.PublicClusterAddr {
			break
		}
		// Best effort see if it's a domain name and if not assume it must match
		host, _, err := net.SplitHostPort(c.Worker.InitialUpstreams[0])
		if err != nil && strings.Contains(err.Error(), globals.MissingPortErrStr) {
			err = nil
			host = c.Worker.InitialUpstreams[0]
		}
		if err == nil {
			ip := net.ParseIP(host)
			if ip == nil {
				// Assume it's a domain name
				break
			}
		}
		fallthrough
	default:
		return fmt.Errorf(`When running a combined controller and worker, it's invalid to specify a "initial_upstreams" or "controllers" key in the worker block with any values other than the controller cluster or upstream worker address/port when using IPs rather than DNS names`)
	}

	return nil
}
