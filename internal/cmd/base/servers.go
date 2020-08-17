package base

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/armon/go-metrics"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/boundary/version"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/shared-secure-libs/configutil"
	"github.com/hashicorp/shared-secure-libs/gatedwriter"
	"github.com/hashicorp/shared-secure-libs/reloadutil"
	"github.com/hashicorp/vault/sdk/helper/base62"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/helper/mlock"
	"github.com/hashicorp/vault/sdk/helper/strutil"
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

	ControllerKMS      wrapping.Wrapper
	WorkerAuthKMS      wrapping.Wrapper
	SecureRandomReader io.Reader

	InmemSink         *metrics.InmemSink
	PrometheusEnabled bool

	ReloadFuncsLock *sync.RWMutex
	ReloadFuncs     map[string][]reloadutil.ReloadFunc

	ShutdownFuncs []func() error

	Listeners []*ServerListener

	DevAuthMethodId string
	DevLoginName    string
	DevPassword     string

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
	padding := 36
	sort.Strings(b.InfoKeys)
	ui.Output(fmt.Sprintf("==> Boundary %s configuration:\n", mode))
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
		ui.Output(fmt.Sprintf("==> Boundary %s started! Log data will stream in below:\n", mode))
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
		for _, purpose := range lnConfig.Purpose {
			purpose = strings.ToLower(purpose)
			if !strutil.StrListContains(allowedPurposes, purpose) {
				return fmt.Errorf("Unknown listener purpose %q", purpose)
			}
		}

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

		lnMux, props, reloadFunc, err := NewListener(lnConfig, b.Logger, ui)
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

func (b *Server) SetupKMSes(ui cli.Ui, config *configutil.SharedConfig, purposes []string) error {
	for _, kms := range config.Seals {
		for _, purpose := range kms.Purpose {
			purpose = strings.ToLower(purpose)
			switch purpose {
			case "":
				return errors.New("KMS block missing 'purpose'")
			case "root", "worker-auth", "config":
			default:
				return fmt.Errorf("Unknown KMS purpose %q", kms.Purpose)
			}

			kmsLogger := b.Logger.ResetNamed(fmt.Sprintf("kms-%s-%s", purpose, kms.Type))

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

			if purpose == "root" {
				b.ControllerKMS = wrapper
			} else {
				b.WorkerAuthKMS = wrapper
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
	gorm.LogFormatter = db.GetGormLogFormatter(b.Logger)
	b.Database.SetLogger(db.GetGormLogger(b.Logger))
	return nil
}

func (b *Server) CreateDevDatabase(dialect string) error {
	c, url, container, err := db.InitDbInDocker(dialect)
	// In case of an error, run the cleanup function.  If we pass all errors, c should be set to a noop
	// function before returning from this method
	defer func() {
		if err := c(); err != nil {
			b.Logger.Error("error cleaning up docker container", "error", err)
		}
	}()

	if err != nil {
		return fmt.Errorf("unable to start dev database with dialect %s: %w", dialect, err)
	}

	b.DevDatabaseCleanupFunc = c
	b.DatabaseUrl = url

	b.InfoKeys = append(b.InfoKeys, "dev database url")
	b.Info["dev database url"] = b.DatabaseUrl
	if container != "" {
		b.InfoKeys = append(b.InfoKeys, "dev database container")
		b.Info["dev database container"] = strings.TrimPrefix(container, "/")
	}

	if err := b.ConnectToDatabase(dialect); err != nil {
		return err
	}

	b.Database.LogMode(true)

	rw := db.New(b.Database)
	repo, err := iam.NewRepository(rw, rw, b.ControllerKMS)
	if err != nil {
		return fmt.Errorf("unable to create repo for org id: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-b.ShutdownCh
		cancel()
	}()

	// Create the dev auth method
	pwRepo, err := password.NewRepository(rw, rw, b.ControllerKMS)
	if err != nil {
		return fmt.Errorf("error creating password repo: %w", err)
	}
	authMethod, err := password.NewAuthMethod(scope.Global.String())
	if err != nil {
		return fmt.Errorf("error creating new in memory auth method: %w", err)
	}
	amId := b.DevAuthMethodId
	if amId == "" {
		amId = "paum_1234567890"
	}
	_, err = pwRepo.CreateAuthMethod(ctx, authMethod, password.WithPublicId(amId))
	if err != nil {
		return fmt.Errorf("error saving auth method to the db: %w", err)
	}

	// Create the dev user
	acctLoginName := b.DevLoginName
	if acctLoginName == "" {
		acctLoginName, err = base62.Random(10)
		if err != nil {
			return fmt.Errorf("unable to generate dev login name: %w", err)
		}
		acctLoginName = strings.ToLower(acctLoginName)
	}
	pw := b.DevPassword
	if pw == "" {
		pw, err = base62.Random(20)
		if err != nil {
			return fmt.Errorf("unable to generate dev password: %w", err)
		}
	}
	acct, err := password.NewAccount(amId, password.WithLoginName(acctLoginName))
	if err != nil {
		return fmt.Errorf("error creating new in memory auth account: %w", err)
	}
	acct, err = pwRepo.CreateAccount(ctx, acct, password.WithPassword(pw))
	if err != nil {
		return fmt.Errorf("error saving auth account to the db: %w", err)
	}

	// Create a role tying them together
	pr, err := iam.NewRole(scope.Global.String())
	if err != nil {
		return fmt.Errorf("error creating in memory role for default dev grants: %w", err)
	}
	pr.Name = "Dev Mode Global Scope Admin Role"
	pr.Description = `Provides admin grants to all authenticated users within the "global" scope`
	defPermsRole, err := repo.CreateRole(ctx, pr)
	if err != nil {
		return fmt.Errorf("error creating role for default dev grants: %w", err)
	}
	if _, err := repo.AddRoleGrants(ctx, defPermsRole.PublicId, defPermsRole.Version, []string{"id=*;actions=*"}); err != nil {
		return fmt.Errorf("error creating grant for default dev grants: %w", err)
	}
	if _, err := repo.AddPrincipalRoles(ctx, defPermsRole.PublicId, defPermsRole.Version+1, []string{"u_auth"}, nil); err != nil {
		return fmt.Errorf("error adding principal to role for default dev grants: %w", err)
	}

	b.InfoKeys = append(b.InfoKeys, "dev auth method id", "dev login name", "dev password")
	b.Info["dev auth method id"] = amId
	b.Info["dev login name"] = acct.GetLoginName()
	b.Info["dev password"] = pw

	// now that we have passed all the error cases, reset c to be a noop so the
	// defer doesn't do anything.
	c = func() error { return nil }
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
