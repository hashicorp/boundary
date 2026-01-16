// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package daemon

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/internal/clientcache/internal/cache"
	cachedb "github.com/hashicorp/boundary/internal/clientcache/internal/db"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/base/logging"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/boundary/internal/util"
	"github.com/hashicorp/boundary/version"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

const (
	// DefaultSearchStaleness is the default amount of time that can pass before
	// a search request causes a blocking refresh to happen for the resources
	// being searched for.
	DefaultSearchStaleness = 30 * time.Second
	// DefaultSearchRefreshTimeout is the default amount of time that a refresh
	// that is blocking a search request can run before timing out.
	DefaultSearchRefreshTimeout = 7 * time.Second
)

// Commander is an interface that provides a way to get an apiClient
// and retrieve the keyring and token information used by a command.
type Commander interface {
	ClientProvider
	ReadTokenFromKeyring(keyringType, tokenName string) (*authtokens.AuthToken, error)
}

// ClientProvider is an interface that provides an api.Client
type ClientProvider interface {
	Client(opt ...base.Option) (*api.Client, error)
}

type CacheServer struct {
	conf *Config

	logger hclog.Logger

	infoKeys []string
	info     map[string]string

	storeUrl string
	store    atomic.Pointer[db.DB]

	tickerWg *sync.WaitGroup
	httpSrv  *http.Server

	shutdownOnce *sync.Once
}

type Config struct {
	ContextCancel          context.CancelFunc
	RefreshInterval        time.Duration
	RecheckSupportInterval time.Duration
	DatabaseUrl            string
	LogLevel               string
	LogFormat              string
	LogWriter              io.Writer
	LogFileName            string
	DotDirectory           string
	RunningInBackground    bool
	// The amount of time since the last refresh that must have passed for a
	// search query to trigger an inline refresh.
	MaxSearchStaleness time.Duration
	// The maximum amount of time a refresh should block a search request from
	// completing before it times out.
	MaxSearchRefreshTimeout time.Duration
	// Force resetting the schema, that is, drop all existing data
	ForceResetSchema bool
}

func (sc *Config) validate(ctx context.Context) error {
	const op = "daemon.(serverConfig).validate"
	switch {
	case util.IsNil(sc.LogWriter):
		return errors.New(ctx, errors.InvalidParameter, op, "missing log writter")
	case util.IsNil(sc.ContextCancel):
		return errors.New(ctx, errors.InvalidParameter, op, "missing contextCancel")
	case sc.DotDirectory == "":
		return errors.New(ctx, errors.InvalidParameter, op, "missing dot directory")
	case sc.RefreshInterval < 0:
		return errors.New(ctx, errors.InvalidParameter, op, "negative refresh interval")
	case sc.RecheckSupportInterval < 0:
		return errors.New(ctx, errors.InvalidParameter, op, "negative recheck support interval")
	case sc.MaxSearchStaleness < 0:
		return errors.New(ctx, errors.InvalidParameter, op, "negative max search staleness")
	}
	return nil
}

// can be called before eventing is setup
func New(ctx context.Context, conf *Config) (*CacheServer, error) {
	const op = "daemon.newServer"
	if err := conf.validate(ctx); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	s := &CacheServer{
		conf:         conf,
		info:         make(map[string]string),
		infoKeys:     make([]string, 0, 20),
		tickerWg:     new(sync.WaitGroup),
		shutdownOnce: new(sync.Once),
	}
	logger, err := s.setupLogging(ctx, conf.LogWriter)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	s.logger = logger
	return s, nil
}

func (s *CacheServer) Shutdown(ctx context.Context) error {
	const op = "daemon.(cacheServer).Shutdown"

	var shutdownErr error
	s.shutdownOnce.Do(func() {
		if s.conf.ContextCancel != nil {
			s.conf.ContextCancel()
		}
		srvCtx, srvCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer srvCancel()
		err := s.httpSrv.Shutdown(srvCtx)
		if err != nil {
			shutdownErr = fmt.Errorf("error shutting down server: %w", err)
			return
		}
		s.tickerWg.Wait()
		event.WriteSysEvent(context.Background(), op, "daemon server shutdown")
		if err := event.SysEventer().FlushNodes(context.Background()); err != nil {
			shutdownErr = fmt.Errorf("error flushing eventer nodes: %w", err)
			return
		}
	})
	return shutdownErr
}

func defaultBoundaryTokenReader(ctx context.Context, cp ClientProvider) (cache.BoundaryTokenReaderFn, error) {
	const op = "daemon.defaultBoundaryTokenReader"
	switch {
	case util.IsNil(cp):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "client provider is nil")
	}
	return func(ctx context.Context, addr, tok string) (*authtokens.AuthToken, error) {
		switch {
		case addr == "":
			return nil, errors.New(ctx, errors.InvalidParameter, op, "address is missing")
		case tok == "":
			return nil, errors.New(ctx, errors.InvalidParameter, op, "auth token is missing")
		}
		atIdParts := strings.SplitN(tok, "_", 4)
		if len(atIdParts) != 3 {
			return nil, errors.New(ctx, errors.InvalidParameter, op, "auth token is malformed")
		}
		atId := strings.Join(atIdParts[:cache.AuthTokenIdSegmentCount], "_")

		c, err := cp.Client(base.WithNoTokenValue())
		if err != nil {
			return nil, err
		}
		if err := c.SetAddr(addr); err != nil {
			return nil, err
		}
		c.SetToken(tok)
		atClient := authtokens.NewClient(c)

		at, err := atClient.Read(ctx, atId)
		if err != nil {
			if api.ErrPermissionDenied.Is(err) {
				return nil, errors.Wrap(ctx, err, op, errors.WithMsg("Failed to get auth token from Boundary"), errors.WithCode(errors.Forbidden), errors.WithoutEvent())
			}
			return nil, errors.Wrap(ctx, err, op, errors.WithoutEvent())
		}
		return at.GetItem(), nil
	}, nil
}

// Serve will fire up the refresh goroutine and the caching API http server as a
// daemon.  The daemon bits are included so it's easy for CLI cmds to start the
// a cache server
func (s *CacheServer) Serve(ctx context.Context, cmd Commander, opt ...Option) error {
	const op = "daemon.(cacheServer).Serve"
	switch {
	case util.IsNil(ctx):
		return errors.New(ctx, errors.InvalidParameter, op, "context is missing")
	}

	opts, err := getOpts(opt...)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if opts.withBoundaryTokenReaderFunc == nil {
		opts.withBoundaryTokenReaderFunc, err = defaultBoundaryTokenReader(ctx, cmd)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
	}

	l, err := listener(ctx, s.conf.DotDirectory)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	s.info["Listening address"] = l.Addr().String()
	s.infoKeys = append(s.infoKeys, "Listening address")

	var store *db.DB
	store, err = openStore(ctx,
		WithUrl(ctx, s.conf.DatabaseUrl),
		WithLogger(ctx, s.logger),
		WithForceResetSchema(ctx, s.conf.ForceResetSchema),
	)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	s.store.Store(store)
	if s.conf.DatabaseUrl != "" {
		s.info["Database URL"] = s.conf.DatabaseUrl
		s.infoKeys = append(s.infoKeys, "Database URL")
	}
	maxSearchRefreshTimeout := DefaultSearchRefreshTimeout
	if s.conf.MaxSearchRefreshTimeout > 0 {
		maxSearchRefreshTimeout = s.conf.MaxSearchRefreshTimeout
	}
	maxSearchStaleness := DefaultSearchStaleness
	if s.conf.MaxSearchStaleness > 0 {
		maxSearchStaleness = s.conf.MaxSearchStaleness
	}
	s.info["Max Search Staleness"] = maxSearchStaleness.String()
	s.infoKeys = append(s.infoKeys, "Max Search Staleness")
	s.info["Max Search Refresh Timeout"] = maxSearchRefreshTimeout.String()
	s.infoKeys = append(s.infoKeys, "Max Search Refresh Timeout")
	s.info["Refresh Interval"] = DefaultRefreshInterval.String()
	s.infoKeys = append(s.infoKeys, "Refresh Interval")
	s.info["Recheck Support Interval"] = DefaultRecheckSupportInterval.String()
	s.infoKeys = append(s.infoKeys, "Recheck Support Interval")

	ticOptions := []Option{}
	if s.conf.RefreshInterval > 0 {
		s.info["Refresh Interval"] = s.conf.RefreshInterval.String()
		ticOptions = append(ticOptions, withRefreshInterval(ctx, s.conf.RefreshInterval))
	}
	if s.conf.RecheckSupportInterval > 0 {
		s.info["Recheck Support Interval"] = s.conf.RecheckSupportInterval.String()
		ticOptions = append(ticOptions, withRecheckSupportInterval(ctx, s.conf.RecheckSupportInterval))
	}

	s.printInfo(ctx)

	repo, err := cache.NewRepository(ctx, s.store.Load(), &sync.Map{}, cmd.ReadTokenFromKeyring, opts.withBoundaryTokenReaderFunc)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	refreshService, err := cache.NewRefreshService(ctx, repo, s.logger, maxSearchStaleness, maxSearchRefreshTimeout)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	tic, err := newRefreshTicker(ctx, refreshService, ticOptions...)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	tickingCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var tickerWg sync.WaitGroup
	tickerWg.Add(2)
	go func() {
		defer tickerWg.Done()
		tic.startRefresh(tickingCtx)
	}()
	go func() {
		defer tickerWg.Done()
		tic.startRecheckCachingSupport(tickingCtx)
	}()

	mux := http.NewServeMux()
	searchFn, err := newSearchHandlerFunc(ctx, repo, refreshService, s.logger)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	mux.Handle("/v1/search", serverMetadataInterceptor(searchFn, s.conf.RunningInBackground))

	statusFn, err := newStatusHandlerFunc(ctx, repo, l.Addr().String(), s.conf.LogFileName)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	mux.Handle("/v1/status", serverMetadataInterceptor(statusFn, s.conf.RunningInBackground))

	logHandlerFn, err := newLogHandlerFunc(ctx)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	mux.Handle("/v1/log", serverMetadataInterceptor(logHandlerFn, s.conf.RunningInBackground))

	tokenFn, err := newTokenHandlerFunc(ctx, repo, tic, s.logger)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	mux.Handle("/v1/tokens", serverMetadataInterceptor(tokenFn, s.conf.RunningInBackground))

	stopFn, err := newStopHandlerFunc(ctx, s.conf.ContextCancel)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	mux.Handle("/v1/stop", serverMetadataInterceptor(stopFn, s.conf.RunningInBackground))

	// Return custom 404 message when requests don't map to any known path.
	mux.Handle("/", serverMetadataInterceptor(new404Func(ctx), s.conf.RunningInBackground))

	logger, err := event.SysEventer().StandardLogger(ctx, "daemon.serve: ", event.ErrorType)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	s.httpSrv = &http.Server{
		Handler:  mux,
		ErrorLog: logger,
		BaseContext: func(net.Listener) context.Context {
			return ctx
		},
	}
	if opts.WithReadyToServeNotificationCh != nil {
		close(opts.WithReadyToServeNotificationCh)
	}
	if err = s.httpSrv.Serve(l); err != nil && err != http.ErrServerClosed && !errors.Is(err, net.ErrClosed) {
		event.WriteSysEvent(ctx, op, "error closing server", "err", err.Error())
	}
	cancel()
	tickerWg.Wait()

	return nil
}

func (s *CacheServer) printInfo(ctx context.Context) {
	const op = "daemon.(cacheServer).printInfo"
	verInfo := version.Get()
	if verInfo.Version != "" {
		s.infoKeys = append(s.infoKeys, "version")
		s.info["version"] = verInfo.FullVersionNumber(false)
	}
	if verInfo.Revision != "" {
		s.info["version sha"] = strings.Trim(verInfo.Revision, "'")
		s.infoKeys = append(s.infoKeys, "version sha")
	}
	s.infoKeys = append(s.infoKeys, "cgo")
	s.info["cgo"] = "disabled"
	if version.CgoEnabled {
		s.info["cgo"] = "enabled"
	}

	// Server configuration output
	padding := 0
	for _, k := range s.infoKeys {
		currPadding := padding - len(k)
		if currPadding < 2 {
			padding = len(k) + 2
		}
	}
	sort.Strings(s.infoKeys)

	output := []string{}
	output = append(output, "==> cache configuration:\n")
	for _, k := range s.infoKeys {
		output = append(output, fmt.Sprintf(
			"%s%s: %s",
			strings.Repeat(" ", padding-len(k)),
			cases.Title(language.English).String(k),
			s.info[k]))
	}
	output = append(output, "")

	// Output the header that the server has started
	output = append(output, "==> cache started! Log data will stream in below:\n")
	event.WriteSysEvent(ctx, op, strings.Join(output, "\n"))
}

func (s *CacheServer) setupLogging(ctx context.Context, w io.Writer) (hclog.Logger, error) {
	const op = "daemon.(Command).setupLogging"
	switch {
	case util.IsNil(w):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "log writer is nil")
	}

	logFormat := logging.StandardFormat
	if s.conf.LogFormat != "" {
		var err error
		logFormat, err = logging.ParseLogFormat(s.conf.LogFormat)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
	}

	logLevel := strings.ToLower(strings.TrimSpace(s.conf.LogLevel))
	if logLevel == "" {
		logLevel = "info"
	}

	// Set up logging
	// Set level based off text value
	var level hclog.Level
	switch logLevel {
	case "trace":
		level = hclog.Trace
	case "debug":
		level = hclog.Debug
	case "notice", "info":
		level = hclog.Info
	case "warn", "warning":
		level = hclog.Warn
	case "err", "error":
		level = hclog.Error
	default:
		return nil, fmt.Errorf("%s: unknown log level: %s", op, logLevel)
	}
	var logLock sync.Mutex
	logger := hclog.New(&hclog.LoggerOptions{
		Output:     w,
		Level:      level,
		JSONFormat: logFormat == logging.JSONFormat,
		Mutex:      &logLock,
	})
	if err := event.InitFallbackLogger(logger); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	s.info["log level"] = level.String()
	s.infoKeys = append(s.infoKeys, "log level")
	s.info["log format"] = logFormat.String()
	s.infoKeys = append(s.infoKeys, "log format")

	var err error
	if err = setupEventing(ctx, logger, &logLock, logFormat, w); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	return logger, nil
}

func setupEventing(ctx context.Context, logger hclog.Logger, serializationLock *sync.Mutex, logFormat logging.LogFormat, w io.Writer) error {
	const op = "daemon.setupEventing"
	switch {
	case util.IsNil(logger):
		return errors.New(ctx, errors.InvalidParameter, op, "logger is missing")
	case util.IsNil(serializationLock):
		return errors.New(ctx, errors.InvalidParameter, op, "serialization lock is missing")
	}
	serverName, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("%s: unable to determine hostname: %w", op, err)
	}
	serverName = fmt.Sprintf("%s/%s", serverName, "cache")

	var sinkFormat event.SinkFormat
	switch logFormat {
	case logging.JSONFormat:
		sinkFormat = event.JSONSinkFormat
	default:
		sinkFormat = event.TextHclogSinkFormat
	}

	cfg := event.EventerConfig{
		AuditEnabled:        false,
		ObservationsEnabled: true,
		SysEventsEnabled:    true,
		Sinks: []*event.SinkConfig{
			{
				Name:       "default",
				EventTypes: []event.Type{event.EveryType},
				Format:     sinkFormat,
				Type:       event.WriterSink,
				WriterConfig: &event.WriterSinkTypeConfig{
					Writer: w,
				},
			},
		},
	}
	if err := event.InitSysEventer(logger, serializationLock, serverName, event.WithEventerConfig(&cfg)); err != nil {
		return fmt.Errorf("%s: unable to initialize system eventer: %w", op, err)
	}
	return nil
}

// openStore will open the underlying store for the db. If no options are
// provided, it will default to an on disk store using the user's home dir +
// ".boundary/cache.db". If a url is provided, it will use that as the store.
// Supported options: WithUrl, WithLogger, WithHomeDir
func openStore(ctx context.Context, opt ...Option) (*db.DB, error) {
	const op = "daemon.openStore"
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	var dbOpts []cachedb.Option
	switch {
	case opts.withUrl != "":
		url, err := parseutil.ParsePath(opts.withUrl)
		if err != nil && !errors.Is(err, parseutil.ErrNotAUrl) {
			return nil, errors.Wrap(ctx, err, op)
		}
		dbOpts = append(dbOpts, cachedb.WithUrl(url))
	default:
		url, err := defaultDbUrl(ctx, opt...)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		dbOpts = append(dbOpts, cachedb.WithUrl(url))
	}
	if !util.IsNil(opts.withLogger) {
		opts.withLogger.Log(hclog.Debug, "Store GormFormatter", "LogLevel", opts.withLogger.GetLevel())
		switch {
		case opts.withLogger.IsDebug():
			dbOpts = append(dbOpts, cachedb.WithGormFormatter(gormDebugLogger{Logger: opts.withLogger}))
			dbOpts = append(dbOpts, cachedb.WithDebug(true))
		default:
			dbOpts = append(dbOpts, cachedb.WithGormFormatter(opts.withLogger))
		}
	}
	dbOpts = append(dbOpts, cachedb.WithForceResetSchema(opts.withForceResetSchema))
	store, err := cachedb.Open(ctx, dbOpts...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return store, nil
}

// defaultDbUrl returns the default db name including the path. It will ensure
// the directory exists by creating it if it doesn't.
func defaultDbUrl(ctx context.Context, opt ...Option) (string, error) {
	const op = "daemon.DefaultDotDirectory"
	opts, err := getOpts(opt...)
	if err != nil {
		return "", errors.Wrap(ctx, err, op)
	}
	if opts.withHomeDir == "" {
		opts.withHomeDir, err = os.UserHomeDir()
		if err != nil {
			return "", errors.Wrap(ctx, err, op)
		}
	}
	dotDir := filepath.Join(opts.withHomeDir, dotDirname)
	if err := os.MkdirAll(dotDir, 0o700); err != nil {
		return "", errors.Wrap(ctx, err, op)
	}
	fileName := filepath.Join(dotDir, dbFileName)
	if _, err := os.Stat(fileName); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return "", errors.Wrap(ctx, err, op)
		}
		file, err := os.OpenFile(fileName, os.O_WRONLY|os.O_CREATE, 0o600)
		if err != nil {
			return "", errors.Wrap(ctx, err, op)
		}
		defer file.Close()
	}
	err = os.Chmod(fileName, 0o600)
	if err != nil {
		return "", errors.Wrap(ctx, err, op)
	}
	return fmt.Sprintf("%s%s", fileName, fkPragma), nil
}

const (
	dotDirname = ".boundary"
	dbFileName = "cache.db"
	fkPragma   = "?_pragma=foreign_keys(1)"
)

type gormDebugLogger struct {
	hclog.Logger
}

func (g gormDebugLogger) Printf(msg string, values ...any) {
	b := new(strings.Builder)
	fmt.Fprintf(b, msg, values...)
	g.Debug(b.String())
}

func getGormLogger(log hclog.Logger) gormDebugLogger {
	return gormDebugLogger{Logger: log}
}
