// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package base

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/cmd/base/internal/metric"
	"github.com/hashicorp/boundary/internal/cmd/base/logging"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/db"
	berrors "github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/boundary/internal/util"
	kms_plugin_assets "github.com/hashicorp/boundary/plugins/kms"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/hashicorp/boundary/version"
	"github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/extras/multi"
	"github.com/hashicorp/go-multierror"
	configutil "github.com/hashicorp/go-secure-stdlib/configutil/v2"
	"github.com/hashicorp/go-secure-stdlib/gatedwriter"
	"github.com/hashicorp/go-secure-stdlib/listenerutil"
	"github.com/hashicorp/go-secure-stdlib/mlock"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/go-secure-stdlib/pluginutil/v2"
	"github.com/hashicorp/go-secure-stdlib/reloadutil"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/mitchellh/cli"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc/grpclog"
)

const (
	// File name to use for storing workerAuth requests
	WorkerAuthReqFile = "auth_request_token"
)

func init() {
	metric.InitializeBuildInfo(prometheus.DefaultRegisterer)
}

type Server struct {
	*Command

	ServerSideShutdownCh chan struct{}

	InfoKeys []string
	Info     map[string]string

	logOutput   io.Writer
	GatedWriter *gatedwriter.Writer
	Logger      hclog.Logger
	CombineLogs bool

	StderrLock *sync.Mutex
	Eventer    *event.Eventer

	// NOTE: Unlike the other wrappers below, if set, DownstreamWorkerAuthKms
	// should always be a PooledWrapper, so that we can allow multiple KMSes to
	// accept downstream connections. As such it's made explicit here.
	DownstreamWorkerAuthKms *multi.PooledWrapper
	RootKms                 wrapping.Wrapper
	WorkerAuthKms           wrapping.Wrapper
	WorkerAuthStorageKms    wrapping.Wrapper
	RecoveryKms             wrapping.Wrapper
	BsrKms                  wrapping.Wrapper
	Kms                     *kms.Kms
	SecureRandomReader      io.Reader

	WorkerAuthDebuggingEnabled *atomic.Bool

	PrometheusRegisterer prometheus.Registerer

	ReloadFuncsLock *sync.RWMutex
	ReloadFuncs     map[string][]reloadutil.ReloadFunc

	ShutdownFuncs []func() error

	Listeners []*ServerListener

	DevPasswordAuthMethodId          string
	DevOidcAuthMethodId              string
	DevLdapAuthMethodId              string
	DevLoginName                     string
	DevPassword                      string
	DevUserId                        string
	DevPasswordAccountId             string
	DevOidcAccountId                 string
	DevUnprivilegedLoginName         string
	DevUnprivilegedPassword          string
	DevUnprivilegedUserId            string
	DevUnprivilegedPasswordAccountId string
	DevUnprivilegedOidcAccountId     string
	DevOrgId                         string
	DevProjectId                     string
	DevHostCatalogId                 string
	DevHostSetId                     string
	DevHostId                        string
	DevTargetId                      string // Target using address.
	DevSecondaryTargetId             string // Target using host sources.
	DevHostAddress                   string // Host address for target using host sources.
	DevTargetAddress                 string // Network address for target with address.
	DevTargetDefaultPort             int
	DevTargetSessionMaxSeconds       int
	DevTargetSessionConnectionLimit  int
	DevLoopbackPluginId              string

	EnabledPlugins []EnabledPlugin
	HostPlugins    map[string]plgpb.HostPluginServiceClient

	DevOidcSetup oidcSetup
	DevLdapSetup ldapSetup

	DatabaseUrl                     string
	DatabaseMaxOpenConnections      int
	DatabaseMaxIdleConnections      *int
	DatabaseConnMaxIdleTimeDuration *time.Duration

	DevDatabaseCleanupFunc func() error

	Database *db.DB
}

// NewServer creates a new Server.
func NewServer(cmd *Command) *Server {
	return &Server{
		Command:                    cmd,
		ServerSideShutdownCh:       make(chan struct{}),
		InfoKeys:                   make([]string, 0, 20),
		Info:                       make(map[string]string),
		SecureRandomReader:         rand.Reader,
		ReloadFuncsLock:            new(sync.RWMutex),
		ReloadFuncs:                make(map[string][]reloadutil.ReloadFunc),
		StderrLock:                 new(sync.Mutex),
		WorkerAuthDebuggingEnabled: new(atomic.Bool),
		PrometheusRegisterer:       prometheus.DefaultRegisterer,
	}
}

// SetupEventing will setup the server's eventer and initialize the "system
// wide" eventer with a pointer to the same eventer
func (b *Server) SetupEventing(ctx context.Context, logger hclog.Logger, serializationLock *sync.Mutex, serverName string, opt ...Option) error {
	const op = "base.(Server).SetupEventing"

	if logger == nil {
		return berrors.New(ctx, berrors.InvalidParameter, op, "missing logger")
	}
	if serializationLock == nil {
		return berrors.New(ctx, berrors.InvalidParameter, op, "missing serialization lock")
	}
	if serverName == "" {
		return berrors.New(ctx, berrors.InvalidParameter, op, "missing server name")
	}
	opts := getOpts(opt...)
	if opts.withEventerConfig != nil {
		if err := opts.withEventerConfig.Validate(); err != nil {
			return berrors.Wrap(ctx, err, op, berrors.WithMsg("invalid eventer config"))
		}
	}
	if opts.withEventerConfig == nil {
		opts.withEventerConfig = event.DefaultEventerConfig()
	}

	if opts.withEventFlags != nil {
		if err := opts.withEventFlags.Validate(); err != nil {
			return berrors.Wrap(ctx, err, op, berrors.WithMsg("invalid event flags"))
		}
		if opts.withEventFlags.Format != "" {
			for i := 0; i < len(opts.withEventerConfig.Sinks); i++ {
				opts.withEventerConfig.Sinks[i].Format = opts.withEventFlags.Format
			}
		}
		if opts.withEventFlags.AuditEnabled != nil {
			opts.withEventerConfig.AuditEnabled = *opts.withEventFlags.AuditEnabled
		}
		if opts.withEventFlags.ObservationsEnabled != nil {
			opts.withEventerConfig.ObservationsEnabled = *opts.withEventFlags.ObservationsEnabled
		}
		if opts.withEventFlags.SysEventsEnabled != nil {
			opts.withEventerConfig.SysEventsEnabled = *opts.withEventFlags.SysEventsEnabled
		}
		if len(opts.withEventFlags.AllowFilters) > 0 {
			for i := 0; i < len(opts.withEventerConfig.Sinks); i++ {
				opts.withEventerConfig.Sinks[i].AllowFilters = opts.withEventFlags.AllowFilters
			}
		}
		if len(opts.withEventFlags.DenyFilters) > 0 {
			for i := 0; i < len(opts.withEventerConfig.Sinks); i++ {
				opts.withEventerConfig.Sinks[i].DenyFilters = opts.withEventFlags.DenyFilters
			}
		}
	}

	e, err := event.NewEventer(
		logger,
		serializationLock,
		serverName,
		*opts.withEventerConfig,
		// Note: this may be nil at this point, it is updated later on in SetupKMSes.
		// There is a cyclic dependency between the eventer and the wrapper, so we instantiate
		// the eventer with a nil wrapper until we have a wrapper to use.
		event.WithAuditWrapper(opts.withEventWrapper),
		event.WithGating(opts.withEventGating))
	if err != nil {
		return berrors.Wrap(ctx, err, op, berrors.WithMsg("unable to create eventer"))
	}
	b.Eventer = e

	if err := event.InitSysEventer(logger, serializationLock, serverName, event.WithEventer(e)); err != nil {
		return berrors.Wrap(ctx, err, op, berrors.WithMsg("unable to initialize system eventer"))
	}

	return nil
}

// AddEventerToContext will add the server eventer to the context provided
func (b *Server) AddEventerToContext(ctx context.Context) (context.Context, error) {
	const op = "base.(Server).AddEventerToContext"
	if b.Eventer == nil {
		return nil, berrors.New(ctx, berrors.InvalidParameter, op, "missing server eventer")
	}
	e, err := event.NewEventerContext(ctx, b.Eventer)
	if err != nil {
		return nil, berrors.Wrap(ctx, err, op, berrors.WithMsg("unable to add eventer to context"))
	}
	return e, nil
}

// SetupLogging sets up the command's logger. This is mostly historical at this
// point since we switched to eventing; however, logging is still used as a
// fallback when events are unable to be sent.
func (b *Server) SetupLogging(flagLogLevel, flagLogFormat, configLogLevel, configLogFormat string) error {
	b.logOutput = os.Stderr
	if b.CombineLogs {
		b.logOutput = os.Stdout
	}
	b.GatedWriter = gatedwriter.NewWriter(b.logOutput)

	// Set up logging
	logLevel, logFormat, err := ProcessLogLevelAndFormat(flagLogLevel, flagLogFormat, configLogLevel, configLogFormat)
	if err != nil {
		return err
	}
	b.Logger = hclog.New(&hclog.LoggerOptions{
		Output: b.GatedWriter,
		Level:  logLevel,
		// Note that if logFormat is either unspecified or json, then
		// the resulting logger's format will be json.
		JSONFormat: logFormat != logging.StandardFormat,
		Mutex:      b.StderrLock,
	})

	if err := event.InitFallbackLogger(b.Logger); err != nil {
		return err
	}

	// create GRPC logger
	namedGRPCLogFaker := b.Logger.Named("grpclogfaker")
	grpclog.SetLogger(&GRPCLogFaker{
		Logger: namedGRPCLogFaker,
		Log:    os.Getenv("BOUNDARY_GRPC_LOGGING") != "",
	})

	b.Info["log level"] = logLevel.String()
	b.InfoKeys = append(b.InfoKeys, "log level")

	// log proxy settings
	// TODO: It would be good to show this but Vault has, or will soon, address
	// the fact that this can log users/passwords if they are part of the proxy
	// URL. When they change things to address that we should update the below
	// logic and re-enable.
	/*
		proxyCfg := httpproxy.FromEnvironment()
		event.WriteSysEvent(context.TODO(), op,
			"proxy environment",
			"http_proxy", proxyCfg.HTTPProxy,
			"https_proxy", proxyCfg.HTTPSProxy,
			"no_proxy",	proxyCfg.NoProxy,
		})
	*/
	// Setup gorm logging

	return nil
}

func (b *Server) ReleaseLogGate() error {
	// Release the log gate.
	b.Logger.(hclog.OutputResettable).ResetOutputWithFlush(&hclog.LoggerOptions{
		Output: b.logOutput,
	}, b.GatedWriter)
	if b.Eventer != nil {
		return b.Eventer.ReleaseGate()
	}
	return nil
}

func (b *Server) StorePidFile(pidPath string) error {
	// Quit fast if no pidfile
	if pidPath == "" {
		return nil
	}

	// Open the PID file
	pidFile, err := os.OpenFile(pidPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("could not open pid file: %w", err)
	}
	defer pidFile.Close()

	// Write out the PID
	pid := os.Getpid()
	_, err = pidFile.WriteString(fmt.Sprintf("%d", pid))
	if err != nil {
		return fmt.Errorf("could not write to pid file: %w", err)
	}

	b.ShutdownFuncs = append(b.ShutdownFuncs, func() error {
		if err := b.RemovePidFile(pidPath); err != nil {
			return fmt.Errorf("Error deleting the PID file: %w", err)
		}
		return nil
	})

	return nil
}

func (b *Server) RemovePidFile(pidPath string) error {
	if pidPath == "" {
		return nil
	}
	return os.Remove(pidPath)
}

func (b *Server) StoreWorkerAuthReq(authReq, workerAuthReqPath string) error {
	// Quit fast if no workerAuthReqFile
	if workerAuthReqPath == "" {
		return nil
	}
	workerAuthReqFilePath := filepath.Join(workerAuthReqPath, WorkerAuthReqFile)

	// Open the workerAuthReq file
	workerAuthReqFile, err := os.OpenFile(workerAuthReqFilePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return fmt.Errorf("could not open file for worker auth request: %w", err)
	}
	defer workerAuthReqFile.Close()

	// Write out the workerAuthRequest
	_, err = workerAuthReqFile.WriteString(authReq)
	if err != nil {
		return fmt.Errorf("could not write to file for worker auth request: %w", err)
	}

	return nil
}

func (b *Server) PrintInfo(ui cli.Ui) {
	verInfo := version.Get()
	if verInfo.Version != "" {
		b.InfoKeys = append(b.InfoKeys, "version")
		b.Info["version"] = verInfo.FullVersionNumber(false)
	}
	if verInfo.Revision != "" {
		b.Info["version sha"] = strings.Trim(verInfo.Revision, "'")
		b.InfoKeys = append(b.InfoKeys, "version sha")
	}
	b.InfoKeys = append(b.InfoKeys, "cgo")
	b.Info["cgo"] = "disabled"
	if version.CgoEnabled {
		b.Info["cgo"] = "enabled"
	}

	// Server configuration output
	padding := 0
	for _, k := range b.InfoKeys {
		currPadding := padding - len(k)
		if currPadding < 2 {
			padding = len(k) + 2
		}
	}
	sort.Strings(b.InfoKeys)
	ui.Output("==> Boundary server configuration:\n")
	for _, k := range b.InfoKeys {
		ui.Output(fmt.Sprintf(
			"%s%s: %s",
			strings.Repeat(" ", padding-len(k)),
			strings.Title(k),
			b.Info[k]))
	}
	ui.Output("")

	// Output the header that the server has started
	if !b.CombineLogs {
		ui.Output("==> Boundary server started! Log data will stream in below:\n")
	}
}

func (b *Server) SetupListeners(ui cli.Ui, config *configutil.SharedConfig, allowedPurposes []string) error {
	// Initialize the listeners
	b.Listeners = make([]*ServerListener, 0, len(config.Listeners))
	// Make sure we close everything before we exit
	// If we successfully started a controller we'll have done this anyways so
	// we ignore errors
	b.ShutdownFuncs = append(b.ShutdownFuncs, func() error {
		for _, ln := range b.Listeners {
			if ln.ProxyListener != nil {
				ln.ProxyListener.Close()
			}
			if ln.ClusterListener != nil {
				ln.ClusterListener.Close()
			}
			if ln.ApiListener != nil {
				ln.ApiListener.Close()
			}
			if ln.OpsListener != nil {
				ln.OpsListener.Close()
			}
		}
		return nil
	})

	b.ReloadFuncsLock.Lock()
	defer b.ReloadFuncsLock.Unlock()

	for i, lnConfig := range config.Listeners {
		if len(lnConfig.Purpose) != 1 {
			return fmt.Errorf("Invalid size of listener purposes (%d)", len(lnConfig.Purpose))
		}
		purpose := strings.ToLower(lnConfig.Purpose[0])
		if !strutil.StrListContains(allowedPurposes, purpose) {
			return fmt.Errorf("Unknown listener purpose %q", purpose)
		}
		lnConfig.Purpose[0] = purpose

		if lnConfig.TLSCipherSuites == nil {
			lnConfig.TLSCipherSuites = []uint16{
				// 1.3
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_CHACHA20_POLY1305_SHA256,
				// 1.2
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			}
		}

		ln, props, reloadFunc, err := NewListener(lnConfig, ui)
		if err != nil {
			return fmt.Errorf("Error initializing listener of type %s: %w", lnConfig.Type, err)
		}

		// CORS props
		if purpose == "api" {
			if lnConfig.CorsEnabled != nil && *lnConfig.CorsEnabled {
				props["cors_enabled"] = "true"
				props["cors_allowed_origins"] = fmt.Sprintf("%v", lnConfig.CorsAllowedOrigins)
				props["cors_allowed_headers"] = fmt.Sprintf("%v", lnConfig.CorsAllowedHeaders)
			} else {
				props["cors_enabled"] = "false"
			}
		}

		// X-Forwarded-For props
		{
			if len(lnConfig.XForwardedForAuthorizedAddrs) > 0 {
				props["x_forwarded_for_authorized_addrs"] = fmt.Sprintf("%v", lnConfig.XForwardedForAuthorizedAddrs)
				props["x_forwarded_for_reject_not_present"] = strconv.FormatBool(lnConfig.XForwardedForRejectNotPresent)
				props["x_forwarded_for_hop_skips"] = "0"
			}

			if lnConfig.XForwardedForHopSkips > 0 {
				props["x_forwarded_for_hop_skips"] = fmt.Sprintf("%d", lnConfig.XForwardedForHopSkips)
			}
		}

		if reloadFunc != nil {
			relSlice := b.ReloadFuncs["listeners"]
			relSlice = append(relSlice, reloadFunc)
			b.ReloadFuncs["listeners"] = relSlice
		}

		if lnConfig.MaxRequestSize == 0 {
			lnConfig.MaxRequestSize = globals.DefaultMaxRequestSize
		}
		// TODO: We don't actually limit this yet.
		// props["max_request_size"] = fmt.Sprintf("%d", lnConfig.MaxRequestSize)

		if lnConfig.MaxRequestDuration == 0 {
			lnConfig.MaxRequestDuration = globals.DefaultMaxRequestDuration
		}
		props["max_request_duration"] = lnConfig.MaxRequestDuration.String()

		serverListener := &ServerListener{
			Config: lnConfig,
		}

		switch purpose {
		case "api":
			serverListener.ApiListener = ln
		case "cluster":
			serverListener.ClusterListener = ln
		case "proxy":
			serverListener.ProxyListener = ln
		case "ops":
			serverListener.OpsListener = ln
		}

		b.Listeners = append(b.Listeners, serverListener)

		props["purpose"] = strings.Join(lnConfig.Purpose, ",")

		// Store the listener props for output later
		key := fmt.Sprintf("listener %d", i+1)
		propsList := make([]string, 0, len(props))
		for k, v := range props {
			propsList = append(propsList, fmt.Sprintf(
				"%s: %q", k, v))
		}
		sort.Strings(propsList)
		b.InfoKeys = append(b.InfoKeys, key)
		b.Info[key] = fmt.Sprintf(
			"%s (%s)", lnConfig.Type, strings.Join(propsList, ", "))
	}

	return nil
}

// SetupKMSes takes in a parsed config, does some minor checking on purposes,
// and sends each off to configutil to instantiate a wrapper.
func (b *Server) SetupKMSes(ctx context.Context, ui cli.Ui, config *config.Config, opt ...Option) error {
	sharedConfig := config.SharedConfig
	var pluginLogger hclog.Logger
	var err error
	var previousRootKms wrapping.Wrapper
	purposeCount := map[string]uint{}
	for _, kms := range sharedConfig.Seals {
		for _, purpose := range kms.Purpose {
			purpose = strings.ToLower(purpose)
			purposeCount[purpose] = purposeCount[purpose] + 1
			switch purpose {
			case "":
				return errors.New("KMS block missing 'purpose'")
			case globals.KmsPurposeRoot,
				globals.KmsPurposePreviousRoot,
				globals.KmsPurposeConfig,
				globals.KmsPurposeWorkerAuth,
				globals.KmsPurposeDownstreamWorkerAuth,
				globals.KmsPurposeWorkerAuthStorage,
				globals.KmsPurposeBsr:
			case globals.KmsPurposeRecovery:
				if config.Controller != nil && config.DevRecoveryKey != "" {
					kms.Config["key"] = config.DevRecoveryKey
				}
			default:
				return fmt.Errorf("Unknown KMS purpose %q", kms.Purpose)
			}

			if pluginLogger == nil {
				pluginLogger, err = event.NewHclogLogger(b.Context, b.Eventer)
				if err != nil {
					return fmt.Errorf("Error creating KMS plugin logger: %w", err)
				}
			}

			// This can be modified by configutil so store the original value
			origPurpose := kms.Purpose
			kms.Purpose = []string{purpose}

			wrapper, cleanupFunc, wrapperConfigError := configutil.ConfigureWrapper(
				ctx,
				kms,
				&b.InfoKeys,
				&b.Info,
				configutil.WithPluginOptions(
					pluginutil.WithPluginsMap(kms_plugin_assets.BuiltinKmsPlugins()),
					pluginutil.WithPluginsFilesystem(kms_plugin_assets.KmsPluginPrefix, kms_plugin_assets.FileSystem()),
					pluginutil.WithPluginExecutionDirectory(config.Plugins.ExecutionDir),
				),
				configutil.WithLogger(pluginLogger.Named(kms.Type).With("purpose", fmt.Sprintf("%s-%d", purpose, purposeCount[purpose]))),
			)
			if wrapperConfigError != nil {
				return fmt.Errorf(
					"Error parsing KMS configuration: %s", wrapperConfigError)
			}
			if wrapper == nil {
				return fmt.Errorf(
					"After configuration nil KMS returned, KMS type was %s", kms.Type)
			}
			if ifWrapper, ok := wrapper.(wrapping.InitFinalizer); ok {
				if err := ifWrapper.Init(ctx); err != nil && !errors.Is(err, wrapping.ErrFunctionNotImplemented) {
					return fmt.Errorf("Error initializing KMS: %w", err)
				}
				// Ensure that the seal finalizer is called, even if using verify-only
				b.ShutdownFuncs = append(b.ShutdownFuncs, func() error {
					if err := ifWrapper.Finalize(context.Background()); err != nil && !errors.Is(err, wrapping.ErrFunctionNotImplemented) {
						return fmt.Errorf("Error finalizing kms of type %s and purpose %s: %v", kms.Type, purpose, err)
					}

					return nil
				})
			}
			if cleanupFunc != nil {
				b.ShutdownFuncs = append(b.ShutdownFuncs, func() error {
					return cleanupFunc()
				})
			}

			kms.Purpose = origPurpose
			switch purpose {
			case globals.KmsPurposePreviousRoot:
				if previousRootKms != nil {
					return fmt.Errorf("Duplicate KMS block for purpose '%s'. You may need to remove all but the last KMS block for this purpose.", purpose)
				}
				previousRootKms = wrapper
			case globals.KmsPurposeRoot:
				if b.RootKms != nil {
					return fmt.Errorf("Duplicate KMS block for purpose '%s'. You may need to remove all but the last KMS block for this purpose.", purpose)
				}
				b.RootKms = wrapper
			case globals.KmsPurposeWorkerAuth:
				if b.WorkerAuthKms != nil {
					return fmt.Errorf("Duplicate KMS block for purpose '%s'. You may need to remove all but the last KMS block for this purpose.", purpose)
				}
				b.WorkerAuthKms = wrapper
			case globals.KmsPurposeDownstreamWorkerAuth:
				if b.DownstreamWorkerAuthKms == nil {
					b.DownstreamWorkerAuthKms, err = multi.NewPooledWrapper(ctx, wrapper)
					if err != nil {
						return fmt.Errorf("Error instantiating pooled wrapper for downstream worker auth: %w.", err)
					}
				} else {
					added, err := b.DownstreamWorkerAuthKms.AddWrapper(ctx, wrapper)
					if err != nil {
						return fmt.Errorf("Error adding additional wrapper to downstream worker auth wrapper pool: %w.", err)
					}
					if !added {
						return fmt.Errorf("Wrapper already added to downstream worker auth wrapper pool.")
					}
				}
			case globals.KmsPurposeWorkerAuthStorage:
				if b.WorkerAuthStorageKms != nil {
					return fmt.Errorf("Duplicate KMS block for purpose '%s'. You may need to remove all but the last KMS block for this purpose.", purpose)
				}
				b.WorkerAuthStorageKms = wrapper
			case globals.KmsPurposeBsr:
				if b.BsrKms != nil {
					return fmt.Errorf("Duplicate KMS block for purpose '%s'. You may need to remove all but the last KMS block for this purpose.", purpose)
				}
				b.BsrKms = wrapper
			case globals.KmsPurposeRecovery:
				if b.RecoveryKms != nil {
					return fmt.Errorf("Duplicate KMS block for purpose '%s'. You may need to remove all but the last KMS block for this purpose.", purpose)
				}
				b.RecoveryKms = wrapper
			case globals.KmsPurposeConfig:
				// Do nothing, can be set in same file but not needed at runtime
				continue
			default:
				return fmt.Errorf("KMS purpose of %q is unknown", purpose)
			}
		}
	}

	// Handle previous root KMS
	if previousRootKms != nil {
		if util.IsNil(b.RootKms) {
			return fmt.Errorf("KMS block contains '%s' without '%s'", globals.KmsPurposePreviousRoot, globals.KmsPurposeRoot)
		}
		mw, err := multi.NewPooledWrapper(ctx, previousRootKms)
		if err != nil {
			return fmt.Errorf("failed to create multi wrapper: %w", err)
		}
		ok, err := mw.SetEncryptingWrapper(ctx, b.RootKms)
		if err != nil {
			return fmt.Errorf("failed to set root wrapper as active in multi wrapper: %w", err)
		}
		if !ok {
			return fmt.Errorf("KMS blocks with purposes '%s' and '%s' must have different key IDs", globals.KmsPurposeRoot, globals.KmsPurposePreviousRoot)
		}
		b.RootKms = mw
	}

	// prepare a secure random reader
	b.SecureRandomReader, err = configutil.CreateSecureRandomReaderFunc(config.SharedConfig, b.RootKms)
	if err != nil {
		return err
	}

	// This might not be the _best_ place for this but we have access to config
	// here
	b.Info["mlock"] = fmt.Sprintf(
		"supported: %v, enabled: %v",
		mlock.Supported(), !config.DisableMlock && mlock.Supported())
	b.InfoKeys = append(b.InfoKeys, "mlock")

	return nil
}

func (b *Server) RunShutdownFuncs() error {
	var mErr *multierror.Error
	for _, f := range b.ShutdownFuncs {
		if err := f(); err != nil {
			mErr = multierror.Append(mErr, err)
		}
	}
	return mErr.ErrorOrNil()
}

// OpenAndSetServerDatabase calls OpenDatabase and sets its result *db.DB to the Server's
// `Database` field.
func (b *Server) OpenAndSetServerDatabase(ctx context.Context, dialect string) error {
	dbase, err := b.OpenDatabase(ctx, dialect, b.DatabaseUrl)
	if err != nil {
		return err
	}
	b.Database = dbase
	return nil
}

// OpenDatabase creates a database connection with the given URL and returns it to the caller.
// It supports various configuration options - The values must be set on the Server object
// beforehand.
func (b *Server) OpenDatabase(ctx context.Context, dialect, url string) (*db.DB, error) {
	dbType, err := db.StringToDbType(dialect)
	if err != nil {
		return nil, fmt.Errorf("unable to create db object with dialect %s: %w", dialect, err)
	}

	opts := []db.Option{
		db.WithMaxOpenConnections(b.DatabaseMaxOpenConnections),
		db.WithMaxIdleConnections(b.DatabaseMaxIdleConnections),
		db.WithConnMaxIdleTimeDuration(b.DatabaseConnMaxIdleTimeDuration),
	}
	if os.Getenv("BOUNDARY_DISABLE_GORM_FORMATTER") == "" {
		opts = append(opts, db.WithGormFormatter(b.Logger))
	}

	dbase, err := db.Open(ctx, dbType, url, opts...)
	if err != nil {
		return nil, fmt.Errorf("unable to create db object with dialect %s: %w", dialect, err)
	}

	return dbase, nil
}

func (b *Server) CreateGlobalKmsKeys(ctx context.Context) error {
	rw := db.New(b.Database)

	kmsCache, err := kms.New(ctx, rw, rw)
	if err != nil {
		return fmt.Errorf("error creating kms cache: %w", err)
	}
	if err := kmsCache.AddExternalWrappers(
		b.Context,
		kms.WithRootWrapper(b.RootKms),
	); err != nil {
		return fmt.Errorf("error adding config keys to kms: %w", err)
	}

	if err = kmsCache.CreateKeys(ctx, scope.Global.String(), kms.WithRandomReader(b.SecureRandomReader)); err != nil {
		return fmt.Errorf("error creating global scope kms keys: %w", err)
	}

	return nil
}

func (b *Server) DestroyDevDatabase(ctx context.Context) error {
	if b.Database != nil {
		if err := b.Database.Close(ctx); err != nil {
			return err
		}
	}
	if b.DevDatabaseCleanupFunc != nil {
		return b.DevDatabaseCleanupFunc()
	}
	return nil
}

func (b *Server) SetupWorkerPublicAddress(conf *config.Config, flagValue string) error {
	if conf.Worker == nil {
		conf.Worker = new(config.Worker)
	}
	if flagValue != "" {
		conf.Worker.PublicAddr = flagValue
	}
	if conf.Worker.PublicAddr == "" {
	FindAddr:
		for _, listener := range conf.Listeners {
			for _, purpose := range listener.Purpose {
				if purpose == "proxy" {
					conf.Worker.PublicAddr = listener.Address
					break FindAddr
				}
			}
		}
	} else {
		var err error
		conf.Worker.PublicAddr, err = parseutil.ParsePath(conf.Worker.PublicAddr)
		if err != nil && !errors.Is(err, parseutil.ErrNotAUrl) {
			return fmt.Errorf("Error parsing public addr: %w", err)
		}

		conf.Worker.PublicAddr, err = listenerutil.ParseSingleIPTemplate(conf.Worker.PublicAddr)
		if err != nil {
			return fmt.Errorf("Error parsing IP template on worker public addr: %w", err)
		}
	}

	host, port, err := net.SplitHostPort(conf.Worker.PublicAddr)
	if err != nil {
		if strings.Contains(err.Error(), "missing port") {
			port = "9202"
			host = conf.Worker.PublicAddr
		} else {
			return fmt.Errorf("Error splitting public adddress host/port: %w", err)
		}
	}
	conf.Worker.PublicAddr = net.JoinHostPort(host, port)
	return nil
}

// MakeSighupCh returns a channel that can be used for SIGHUP
// reloading. This channel will send a message for every
// SIGHUP received.
func MakeSighupCh() chan struct{} {
	resultCh := make(chan struct{})

	signalCh := make(chan os.Signal, 4)
	signal.Notify(signalCh, syscall.SIGHUP)
	go func() {
		for {
			<-signalCh
			resultCh <- struct{}{}
		}
	}()
	return resultCh
}
