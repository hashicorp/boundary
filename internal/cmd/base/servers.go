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
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/armon/go-metrics"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/hashicorp/boundary/internal/docker"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/boundary/sdk/strutil"
	"github.com/hashicorp/boundary/version"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/shared-secure-libs/configutil"
	"github.com/hashicorp/shared-secure-libs/gatedwriter"
	"github.com/hashicorp/shared-secure-libs/reloadutil"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/helper/mlock"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/jinzhu/gorm"
	"github.com/mitchellh/cli"
	"google.golang.org/grpc/grpclog"
)

type Server struct {
	*Command

	InfoKeys []string
	Info     map[string]string

	logOutput   io.Writer
	GatedWriter *gatedwriter.Writer
	Logger      hclog.Logger
	CombineLogs bool
	LogLevel    hclog.Level

	RootKms            wrapping.Wrapper
	WorkerAuthKms      wrapping.Wrapper
	RecoveryKms        wrapping.Wrapper
	Kms                *kms.Kms
	SecureRandomReader io.Reader

	InmemSink         *metrics.InmemSink
	PrometheusEnabled bool

	ReloadFuncsLock *sync.RWMutex
	ReloadFuncs     map[string][]reloadutil.ReloadFunc

	ShutdownFuncs []func() error

	Listeners []*ServerListener

	DevPasswordAuthMethodId         string
	DevOidcAuthMethodId             string
	DevLoginName                    string
	DevPassword                     string
	DevUserId                       string
	DevUnprivilegedLoginName        string
	DevUnprivilegedPassword         string
	DevUnprivilegedUserId           string
	DevOrgId                        string
	DevProjectId                    string
	DevHostCatalogId                string
	DevHostSetId                    string
	DevHostId                       string
	DevTargetId                     string
	DevHostAddress                  string
	DevTargetDefaultPort            int
	DevTargetSessionMaxSeconds      int
	DevTargetSessionConnectionLimit int

	DatabaseUrl            string
	DevDatabaseCleanupFunc func() error

	Database *gorm.DB
}

func NewServer(cmd *Command) *Server {
	return &Server{
		Command:            cmd,
		InfoKeys:           make([]string, 0, 20),
		Info:               make(map[string]string),
		SecureRandomReader: rand.Reader,
		ReloadFuncsLock:    new(sync.RWMutex),
		ReloadFuncs:        make(map[string][]reloadutil.ReloadFunc),
	}
}

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
		// Note that if logFormat is either unspecified or standard, then
		// the resulting logger's format will be standard.
		JSONFormat: logFormat == logging.JSONFormat,
	})

	// create GRPC logger
	namedGRPCLogFaker := b.Logger.Named("grpclogfaker")
	grpclog.SetLogger(&GRPCLogFaker{
		Logger: namedGRPCLogFaker,
		Log:    os.Getenv("BOUNDARY_GRPC_LOGGING") != "",
	})

	b.Info["log level"] = logLevel.String()
	b.InfoKeys = append(b.InfoKeys, "log level")

	b.LogLevel = logLevel

	// log proxy settings
	// TODO: It would be good to show this but Vault has, or will soon, address
	// the fact that this can log users/passwords if they are part of the proxy
	// URL. When they change things to address that we should update the below
	// logic and re-enable.
	/*
		proxyCfg := httpproxy.FromEnvironment()
		b.Logger.Info("proxy environment", "http_proxy", proxyCfg.HTTPProxy,
			"https_proxy", proxyCfg.HTTPSProxy, "no_proxy", proxyCfg.NoProxy)
	*/
	// Setup gorm logging

	return nil
}

func (b *Server) ReleaseLogGate() {
	// Release the log gate.
	b.Logger.(hclog.OutputResettable).ResetOutputWithFlush(&hclog.LoggerOptions{
		Output: b.logOutput,
	}, b.GatedWriter)
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

func (b *Server) SetupMetrics(ui cli.Ui, telemetry *configutil.Telemetry) error {
	// TODO: Figure out a user-agent we want to use for the last param
	// TODO: Do we want different names for different components?
	var err error
	b.InmemSink, _, b.PrometheusEnabled, err = configutil.SetupTelemetry(&configutil.SetupTelemetryOpts{
		Config:      telemetry,
		Ui:          ui,
		ServiceName: "boundary",
		DisplayName: "Boundary",
		UserAgent:   "boundary",
	})
	if err != nil {
		return fmt.Errorf("Error initializing telemetry: %w", err)
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
			ln.Mux.Close()
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
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			}
		}

		lnMux, props, reloadFunc, err := NewListener(lnConfig, b.Logger, ui)
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

		b.Listeners = append(b.Listeners, &ServerListener{
			Mux:    lnMux,
			Config: lnConfig,
		})

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

func (b *Server) SetupKMSes(ui cli.Ui, config *config.Config) error {
	sharedConfig := config.SharedConfig
	for _, kms := range sharedConfig.Seals {
		for _, purpose := range kms.Purpose {
			purpose = strings.ToLower(purpose)
			switch purpose {
			case "":
				return errors.New("KMS block missing 'purpose'")
			case "root", "worker-auth", "config":
			case "recovery":
				if config.Controller != nil && config.DevRecoveryKey != "" {
					kms.Config["key"] = config.DevRecoveryKey
				}
			default:
				return fmt.Errorf("Unknown KMS purpose %q", kms.Purpose)
			}

			kmsLogger := b.Logger.ResetNamed(fmt.Sprintf("kms-%s-%s", purpose, kms.Type))

			origPurpose := kms.Purpose
			kms.Purpose = []string{purpose}
			wrapper, wrapperConfigError := configutil.ConfigureWrapper(kms, &b.InfoKeys, &b.Info, kmsLogger)
			kms.Purpose = origPurpose
			if wrapperConfigError != nil {
				if !errwrap.ContainsType(wrapperConfigError, new(logical.KeyNotFoundError)) {
					return fmt.Errorf(
						"Error parsing KMS configuration: %s", wrapperConfigError)
				}
			}
			if wrapper == nil {
				return fmt.Errorf(
					"After configuration nil KMS returned, KMS type was %s", kms.Type)
			}

			switch purpose {
			case "root":
				b.RootKms = wrapper
			case "worker-auth":
				b.WorkerAuthKms = wrapper
			case "recovery":
				b.RecoveryKms = wrapper
			case "config":
				// Do nothing, can be set in same file but not needed at runtime
			default:
				return fmt.Errorf("KMS purpose of %q is unknown", purpose)
			}

			// Ensure that the seal finalizer is called, even if using verify-only
			b.ShutdownFuncs = append(b.ShutdownFuncs, func() error {
				if err := wrapper.Finalize(context.Background()); err != nil {
					return fmt.Errorf("Error finalizing kms of type %s and purpose %s: %v", kms.Type, purpose, err)
				}

				return nil
			})
		}
	}

	// prepare a secure random reader
	var err error
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

func (b *Server) ConnectToDatabase(dialect string) error {
	dbase, err := gorm.Open(dialect, b.DatabaseUrl)
	if err != nil {
		return fmt.Errorf("unable to create db object with dialect %s: %w", dialect, err)
	}

	b.Database = dbase
	if os.Getenv("BOUNDARY_DISABLE_GORM_FORMATTER") == "" {
		gorm.LogFormatter = db.GetGormLogFormatter(b.Logger)
		b.Database.SetLogger(db.GetGormLogger(b.Logger))
	}
	return nil
}

func (b *Server) CreateDevDatabase(ctx context.Context, dialect string, opt ...Option) error {
	opts := getOpts(opt...)

	var container, url string
	var err error
	var c func() error

	switch b.DatabaseUrl {
	case "":
		c, url, container, err = docker.StartDbInDocker(dialect)
		// In case of an error, run the cleanup function.  If we pass all errors, c should be set to a noop
		// function before returning from this method
		defer func() {
			if !opts.withSkipDatabaseDestruction {
				if c != nil {
					if err := c(); err != nil {
						b.Logger.Error("error cleaning up docker container", "error", err)
					}
				}
			}
		}()
		if err == docker.ErrDockerUnsupported {
			return err
		}
		if err != nil {
			return fmt.Errorf("unable to start dev database with dialect %s: %w", dialect, err)
		}

		// Let migrate store manage the dirty bit since dev DBs should be ephemeral anyways.
		_, err := schema.MigrateStore(ctx, dialect, url)
		if err != nil {
			err = fmt.Errorf("unable to initialize dev database with dialect %s: %w", dialect, err)
			if c != nil {
				err = multierror.Append(err, c())
			}
			return err
		}

		b.DevDatabaseCleanupFunc = c
		b.DatabaseUrl = url

	default:
		// Let migrate store manage the dirty bit since dev DBs should be ephemeral anyways.
		if _, err := schema.MigrateStore(ctx, dialect, b.DatabaseUrl); err != nil {
			err = fmt.Errorf("error initializing store: %w", err)
			if c != nil {
				err = multierror.Append(err, c())
			}
			return err
		}
	}

	b.InfoKeys = append(b.InfoKeys, "dev database url")
	b.Info["dev database url"] = b.DatabaseUrl
	if container != "" {
		b.InfoKeys = append(b.InfoKeys, "dev database container")
		b.Info["dev database container"] = strings.TrimPrefix(container, "/")
	}

	if err := b.ConnectToDatabase(dialect); err != nil {
		if c != nil {
			err = multierror.Append(err, c())
		}
		return err
	}

	b.Database.LogMode(true)

	if err := b.CreateGlobalKmsKeys(ctx); err != nil {
		if c != nil {
			err = multierror.Append(err, c())
		}
		return err
	}

	if _, err := b.CreateInitialLoginRole(ctx); err != nil {
		if c != nil {
			err = multierror.Append(err, c())
		}
		return err
	}

	if opts.withSkipAuthMethodCreation {
		// now that we have passed all the error cases, reset c to be a noop so the
		// defer doesn't do anything.
		c = func() error { return nil }
		return nil
	}

	if _, _, err := b.CreateInitialPasswordAuthMethod(ctx); err != nil {
		return err
	}

	if opts.withSkipScopesCreation {
		// now that we have passed all the error cases, reset c to be a noop so the
		// defer doesn't do anything.
		c = func() error { return nil }
		return nil
	}

	if _, _, err := b.CreateInitialScopes(ctx); err != nil {
		return err
	}

	if opts.withSkipHostResourcesCreation {
		// now that we have passed all the error cases, reset c to be a noop so the
		// defer doesn't do anything.
		c = func() error { return nil }
		return nil
	}

	if _, _, _, err := b.CreateInitialHostResources(context.Background()); err != nil {
		return err
	}

	if opts.withSkipTargetCreation {
		// now that we have passed all the error cases, reset c to be a noop so the
		// defer doesn't do anything.
		c = func() error { return nil }
		return nil
	}

	if _, err := b.CreateInitialTarget(ctx); err != nil {
		return err
	}

	// now that we have passed all the error cases, reset c to be a noop so the
	// defer doesn't do anything.
	c = func() error { return nil }
	return nil
}

func (b *Server) CreateGlobalKmsKeys(ctx context.Context) error {
	rw := db.New(b.Database)

	kmsRepo, err := kms.NewRepository(rw, rw)
	if err != nil {
		return fmt.Errorf("error creating kms repository: %w", err)
	}
	kmsCache, err := kms.NewKms(kmsRepo)
	if err != nil {
		return fmt.Errorf("error creating kms cache: %w", err)
	}
	if err := kmsCache.AddExternalWrappers(
		kms.WithRootWrapper(b.RootKms),
	); err != nil {
		return fmt.Errorf("error adding config keys to kms: %w", err)
	}

	cancelCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-b.ShutdownCh:
			cancel()
		case <-cancelCtx.Done():
		}
	}()

	_, err = kms.CreateKeysTx(cancelCtx, rw, rw, b.RootKms, b.SecureRandomReader, scope.Global.String())
	if err != nil {
		return fmt.Errorf("error creating global scope kms keys: %w", err)
	}

	return nil
}

func (b *Server) DestroyDevDatabase() error {
	if b.Database != nil {
		b.Database.Close()
	}
	if b.DevDatabaseCleanupFunc != nil {
		return b.DevDatabaseCleanupFunc()
	}
	return nil
}

func (b *Server) SetupControllerPublicClusterAddress(conf *config.Config, flagValue string) error {
	if conf.Controller == nil {
		conf.Controller = new(config.Controller)
	}
	if flagValue != "" {
		conf.Controller.PublicClusterAddr = flagValue
	}
	if conf.Controller.PublicClusterAddr == "" {
	FindAddr:
		for _, listener := range conf.Listeners {
			for _, purpose := range listener.Purpose {
				if purpose == "cluster" {
					conf.Controller.PublicClusterAddr = listener.Address
					break FindAddr
				}
			}
		}
	} else {
		var err error
		conf.Controller.PublicClusterAddr, err = config.ParseAddress(conf.Controller.PublicClusterAddr)
		if err != nil && err != config.ErrNotAUrl {
			return fmt.Errorf("Error parsing public cluster addr: %w", err)
		}
	}
	host, port, err := net.SplitHostPort(conf.Controller.PublicClusterAddr)
	if err != nil {
		if strings.Contains(err.Error(), "missing port") {
			port = "9201"
			host = conf.Controller.PublicClusterAddr
		} else {
			return fmt.Errorf("Error splitting public cluster adddress host/port: %w", err)
		}
	}
	conf.Controller.PublicClusterAddr = net.JoinHostPort(host, port)
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
		conf.Worker.PublicAddr, err = config.ParseAddress(conf.Worker.PublicAddr)
		if err != nil && err != config.ErrNotAUrl {
			return fmt.Errorf("Error parsing public addr: %w", err)
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
