package base

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/armon/go-metrics"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/go-alpnmux"
	"github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault/internalshared/configutil"
	"github.com/hashicorp/vault/internalshared/gatedwriter"
	"github.com/hashicorp/vault/internalshared/reloadutil"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/helper/mlock"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/watchtower/globals"
	"github.com/hashicorp/watchtower/version"
	"github.com/mitchellh/cli"
	"github.com/ory/dockertest/v3"
	"golang.org/x/net/http/httpproxy"
	"google.golang.org/grpc/grpclog"

	_ "github.com/lib/pq"
)

type ServerListener struct {
	Mux          *alpnmux.ALPNMux
	Config       *configutil.Listener
	HTTPServer   *http.Server
	ALPNListener net.Listener
}

type Server struct {
	InfoKeys []string
	Info     map[string]string

	logOutput   io.Writer
	GatedWriter *gatedwriter.Writer
	Logger      hclog.Logger
	CombineLogs bool
	AllLoggers  []hclog.Logger
	LogLevel    hclog.Level

	ControllerKMS      wrapping.Wrapper
	WorkerAuthKMS      wrapping.Wrapper
	SecureRandomReader io.Reader

	InmemSink         *metrics.InmemSink
	PrometheusEnabled bool

	ReloadFuncsLock *sync.RWMutex
	ReloadFuncs     map[string][]reloadutil.ReloadFunc

	ShutdownFuncs []func() error

	Listeners []*ServerListener

	DevDatabasePassword string
	DevDatabaseName     string
	DevDatabasePort     string

	dockertestPool     *dockertest.Pool
	dockertestResource *dockertest.Resource
}

func NewServer() *Server {
	return &Server{
		InfoKeys:           make([]string, 0, 20),
		Info:               make(map[string]string),
		AllLoggers:         make([]hclog.Logger, 0),
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
	// Create allLoggers which can be used to HUP the various derived loggers
	b.AllLoggers = []hclog.Logger{b.Logger}

	// create GRPC logger
	namedGRPCLogFaker := b.Logger.Named("grpclogfaker")
	b.AllLoggers = append(b.AllLoggers, namedGRPCLogFaker)
	grpclog.SetLogger(&GRPCLogFaker{
		Logger: namedGRPCLogFaker,
		Log:    os.Getenv("WATCHTOWER_GRPC_LOGGING") != "",
	})

	b.Info["log level"] = logLevel.String()
	b.InfoKeys = append(b.InfoKeys, "log level")

	b.LogLevel = logLevel

	// log proxy settings
	proxyCfg := httpproxy.FromEnvironment()
	b.Logger.Info("proxy environment", "http_proxy", proxyCfg.HTTPProxy,
		"https_proxy", proxyCfg.HTTPSProxy, "no_proxy", proxyCfg.NoProxy)

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
	pidFile, err := os.OpenFile(pidPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
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
	b.InmemSink, b.PrometheusEnabled, err = configutil.SetupTelemetry(telemetry, ui, "watchtower", "Watchtower", "watchtower")
	if err != nil {
		return fmt.Errorf("Error initializing telemetry: %w", err)
	}

	return nil
}

func (b *Server) PrintInfo(ui cli.Ui, mode string) {
	b.InfoKeys = append(b.InfoKeys, "version")
	verInfo := version.Get()
	b.Info["version"] = verInfo.FullVersionNumber(false)
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
	padding := 24
	sort.Strings(b.InfoKeys)
	ui.Output(fmt.Sprintf("==> Watchtower %s configuration:\n", mode))
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
		ui.Output(fmt.Sprintf("==> Watchtower %s started! Log data will stream in below:\n", mode))
	}
}

func (b *Server) SetupListeners(ui cli.Ui, config *configutil.SharedConfig) error {
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
		// Override for now
		// TODO: Way to configure
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

		lnMux, props, reloadFunc, err := NewListener(lnConfig, b.GatedWriter, ui)
		if err != nil {
			return fmt.Errorf("Error initializing listener of type %s: %w", lnConfig.Type, err)
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
			relSlice := b.ReloadFuncs["listener|"+lnConfig.Type]
			relSlice = append(relSlice, reloadFunc)
			b.ReloadFuncs["listener|"+lnConfig.Type] = relSlice
		}

		if lnConfig.MaxRequestSize == 0 {
			lnConfig.MaxRequestSize = globals.DefaultMaxRequestSize
		}
		props["max_request_size"] = fmt.Sprintf("%d", lnConfig.MaxRequestSize)

		if lnConfig.MaxRequestDuration == 0 {
			lnConfig.MaxRequestDuration = globals.DefaultMaxRequestDuration
		}
		props["max_request_duration"] = fmt.Sprintf("%s", lnConfig.MaxRequestDuration.String())

		b.Listeners = append(b.Listeners, &ServerListener{
			Mux:    lnMux,
			Config: lnConfig,
		})

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

func (b *Server) SetupKMSes(ui cli.Ui, config *configutil.SharedConfig, size int) error {
	switch len(config.Seals) {
	case size:
		for _, kms := range config.Seals {
			purpose := strings.ToLower(kms.Purpose)
			switch purpose {
			case "":
				return errors.New("KMS block missing 'purpose'")
			case "controller", "worker-auth":
			default:
				return fmt.Errorf("Unknown KMS purpose %q", kms.Purpose)
			}

			kmsLogger := b.Logger.ResetNamed(fmt.Sprintf("kms-%s-%s", purpose, kms.Type))

			b.AllLoggers = append(b.AllLoggers, kmsLogger)
			wrapper, wrapperConfigError := configutil.ConfigureWrapper(kms, &b.InfoKeys, &b.Info, kmsLogger)
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

			if purpose == "controller" {
				b.ControllerKMS = wrapper
			} else {
				b.WorkerAuthKMS = wrapper
			}

			// Ensure that the seal finalizer is called, even if using verify-only
			b.ShutdownFuncs = append(b.ShutdownFuncs, func() error {
				if err := wrapper.Finalize(context.Background()); err != nil {
					return fmt.Errorf("Error finalizing kms of type %s and purpose %s: %v", kms.Type, kms.Purpose, err)
				}

				return nil
			})
		}

	default:
		return fmt.Errorf("Wrong number of KMS blocks provided; expected %d, got %d", size, len(config.Seals))
	}

	// prepare a secure random reader
	var err error
	b.SecureRandomReader, err = configutil.CreateSecureRandomReaderFunc(config, b.ControllerKMS)
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

func (b *Server) RunShutdownFuncs(ui cli.Ui) {
	for _, f := range b.ShutdownFuncs {
		if err := f(); err != nil {
			ui.Error(fmt.Sprintf("Error running a shutdown task: %s", err.Error()))
		}
	}
}

func (b *Server) CreateDevDatabase() error {
	pool, err := dockertest.NewPool("")
	if err != nil {
		return fmt.Errorf("could not connect to docker: %w", err)
	}

	resource, err := pool.Run("postgres", "latest", []string{"POSTGRES_PASSWORD=secret", "POSTGRES_DB=watchtower"})
	if err != nil {
		return fmt.Errorf("could not start resource: %w", err)
	}

	if err := pool.Retry(func() error {
		db, err := sql.Open("postgres", fmt.Sprintf("postgres://postgres:secret@localhost:%s/watchtower?sslmode=disable", resource.GetPort("5432/tcp")))
		if err != nil {
			return fmt.Errorf("error opening postgres dev container: %w", err)
		}
		var mErr *multierror.Error
		if err := db.Ping(); err != nil {
			mErr = multierror.Append(fmt.Errorf("error pinging dev database container: %w", err))
		}
		if err := db.Close(); err != nil {
			mErr = multierror.Append(fmt.Errorf("error closing dev database container: %w", err))
		}
		return mErr.ErrorOrNil()
	}); err != nil {
		return fmt.Errorf("could not connect to docker: %w", err)
	}

	b.dockertestPool = pool
	b.dockertestResource = resource
	b.DevDatabaseName = "watchtower"
	b.DevDatabasePassword = "secret"
	b.DevDatabasePort = resource.GetPort("5432/tcp")

	b.InfoKeys = append(b.InfoKeys, "dev database name", "dev database password", "dev database port")
	b.Info["dev database name"] = "watchtower"
	b.Info["dev database password"] = "secret"
	b.Info["dev database port"] = b.DevDatabasePort
	return nil
}

func (b *Server) DestroyDevDatabase() error {
	if b.dockertestPool == nil {
		return nil
	}

	if b.dockertestResource == nil {
		return errors.New("found a pool for dev database container but no resource")
	}

	return b.dockertestPool.Purge(b.dockertestResource)
}
