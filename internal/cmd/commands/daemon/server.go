// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package daemon

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/base/logging"
	"github.com/hashicorp/boundary/internal/daemon/cache"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/boundary/internal/util"
	"github.com/hashicorp/boundary/version"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
)

// Commander is an interface that provides a way to get an apiClient
// and retrieve the keyring and token information used by a command.
type Commander interface {
	Client(opt ...base.Option) (*api.Client, error)
	DiscoverKeyringTokenInfo() (string, string, error)
	ReadTokenFromKeyring(keyringType, tokenName string) *authtokens.AuthToken
}

type cacheServer struct {
	conf *serverConfig

	infoKeys []string
	info     map[string]string

	storeUrl string
	store    *cache.Store

	tickerWg *sync.WaitGroup
	httpSrv  *http.Server

	shutdownOnce *sync.Once
}

type serverConfig struct {
	contextCancel          context.CancelFunc
	refreshIntervalSeconds int64
	flagDatabaseUrl        string
	flagStoreDebug         bool
	flagLogLevel           string
	flagLogFormat          string
	logWriter              io.Writer
}

func (sc *serverConfig) validate(ctx context.Context) error {
	const op = "daemon.(serverConfig).validate"
	switch {
	case util.IsNil(sc.logWriter):
		return errors.New(ctx, errors.InvalidParameter, op, "missing log writter")
	case util.IsNil(sc.contextCancel):
		return errors.New(ctx, errors.InvalidParameter, op, "missing contextCancel")
	}
	return nil
}

// can be called before eventing is setup
func newServer(ctx context.Context, conf *serverConfig) (*cacheServer, error) {
	const op = "daemon.newServer"
	if err := conf.validate(ctx); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	s := &cacheServer{
		conf:         conf,
		info:         make(map[string]string),
		infoKeys:     make([]string, 0, 20),
		tickerWg:     new(sync.WaitGroup),
		shutdownOnce: new(sync.Once),
	}
	if err := s.setupLogging(ctx, conf.logWriter); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return s, nil
}

func (s *cacheServer) shutdown(ctx context.Context) error {
	const op = "daemon.(cacheServer).Shutdown"

	var shutdownErr error
	s.shutdownOnce.Do(func() {
		if s.conf.contextCancel != nil {
			s.conf.contextCancel()
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

// start will fire up the refresh goroutine and the caching API http server as a
// daemon.  The daemon bits are included so it's easy for CLI cmds to start the
// a cache server
func (s *cacheServer) serve(ctx context.Context, cmd Commander, l net.Listener) error {
	const op = "daemon.(cacheServer).start"
	switch {
	case util.IsNil(ctx):
		return errors.New(ctx, errors.InvalidParameter, op, "context is missing")
	}

	s.info["Listening address"] = l.Addr().String()
	s.infoKeys = append(s.infoKeys, "Listening address")
	s.info["Store debug"] = strconv.FormatBool(s.conf.flagStoreDebug)
	s.infoKeys = append(s.infoKeys, "Store debug")

	var err error
	if s.store, s.storeUrl, err = openStore(ctx, s.conf.flagDatabaseUrl, s.conf.flagStoreDebug); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	s.info["Database URL"] = s.storeUrl
	s.infoKeys = append(s.infoKeys, "Database URL")

	s.printInfo(ctx)

	repo, err := cache.NewRepository(ctx, s.store, cmd.ReadTokenFromKeyring)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	// If we have a token info already, add it to the repository immediately so
	// it can start to get updated.
	func() {
		client, err := cmd.Client()
		if err != nil {
			event.WriteError(ctx, op, err)
			return
		}
		krType, tokName, err := cmd.DiscoverKeyringTokenInfo()
		if err != nil {
			event.WriteError(ctx, op, err)
			return
		}
		if at := cmd.ReadTokenFromKeyring(krType, tokName); at != nil {
			if err := repo.AddKeyringToken(ctx, client.Addr(), cache.KeyringToken{KeyringType: krType, TokenName: tokName, AuthTokenId: at.Id}); err != nil {
				event.WriteError(ctx, op, err)
				return
			}
		}
	}()

	tic, err := newRefreshTicker(ctx, s.conf.refreshIntervalSeconds, repo.Refresh)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	tickingCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var tickerWg sync.WaitGroup
	tickerWg.Add(1)
	go func() {
		defer tickerWg.Done()
		tic.start(tickingCtx)
	}()

	mux := http.NewServeMux()
	searchTargetsFn, err := newSearchTargetsHandlerFunc(ctx, repo)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	mux.HandleFunc("/v1/search", searchTargetsFn)

	tokenFn, err := newTokenHandlerFunc(ctx, repo, tic)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	mux.HandleFunc("/v1/tokens", tokenFn)

	stopFn, err := newStopHandlerFunc(ctx, s.conf.contextCancel)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	mux.Handle("/v1/stop", versionEnforcement(stopFn))

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
	if err = s.httpSrv.Serve(l); err != nil && err != http.ErrServerClosed && !errors.Is(err, net.ErrClosed) {
		event.WriteSysEvent(ctx, op, "error closing server", "err", err.Error())
	}
	cancel()
	tickerWg.Wait()

	return nil
}

func (s *cacheServer) printInfo(ctx context.Context) {
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
			strings.Title(k),
			s.info[k]))
	}
	output = append(output, "")

	// Output the header that the server has started
	output = append(output, "==> cache started! Log data will stream in below:\n")
	event.WriteSysEvent(ctx, op, strings.Join(output, "\n"))
}

func (s *cacheServer) setupLogging(ctx context.Context, w io.Writer) error {
	const op = "daemon.(Command).setupLogging"
	switch {
	case util.IsNil(w):
		return errors.New(ctx, errors.InvalidParameter, op, "log writer is nil")
	}

	logFormat := logging.StandardFormat
	if s.conf.flagLogFormat != "" {
		var err error
		logFormat, err = logging.ParseLogFormat(s.conf.flagLogFormat)
		if err != nil {
			return fmt.Errorf("%s: %w", op, err)
		}
	}

	logLevel := strings.ToLower(strings.TrimSpace(s.conf.flagLogLevel))
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
		return fmt.Errorf("%s: unknown log level: %s", op, logLevel)
	}
	var logLock sync.Mutex
	logger := hclog.New(&hclog.LoggerOptions{
		Output:     w,
		Level:      level,
		JSONFormat: logFormat == logging.JSONFormat,
		Mutex:      &logLock,
	})
	if err := event.InitFallbackLogger(logger); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	s.info["log level"] = level.String()
	s.infoKeys = append(s.infoKeys, "log level")
	s.info["log format"] = logFormat.String()
	s.infoKeys = append(s.infoKeys, "log format")

	var err error
	if err = setupEventing(ctx, logger, &logLock, logFormat, w); err != nil {
		return errors.Wrap(ctx, err, op)
	}

	return nil
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

func openStore(ctx context.Context, url string, flagDebugStore bool) (*cache.Store, string, error) {
	const op = "daemon.openStore"
	var err error
	switch {
	case url != "":
		url, err = parseutil.ParsePath(url)
		if err != nil && !errors.Is(err, parseutil.ErrNotAUrl) {
			return nil, "", errors.Wrap(ctx, err, op)
		}
	default:
		url = cache.DefaultStoreUrl
	}
	store, err := cache.Open(ctx, cache.WithUrl(url), cache.WithDebug(flagDebugStore))
	if err != nil {
		return nil, "", errors.Wrap(ctx, err, op)
	}
	return store, url, nil
}
