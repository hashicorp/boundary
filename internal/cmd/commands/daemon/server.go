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
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/boundary/internal/util"
	"github.com/hashicorp/boundary/version"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/gatedwriter"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/mitchellh/cli"
)

type commander interface {
	Client(opt ...base.Option) (*api.Client, error)
	DiscoverKeyringTokenInfo() (string, string, error)
	ReadTokenFromKeyring(keyringType, tokenName string) *authtokens.AuthToken
}

type cacheServer struct {
	conf *serverConfig

	infoKeys []string
	info     map[string]string
	logger   hclog.Logger
	eventer  *event.Eventer

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
	ui                     cli.Ui
}

func (sc *serverConfig) validate() error {
	return nil
}

// can be called before eventing is setup
func newServer(ctx context.Context, conf serverConfig) (*cacheServer, error) {
	const op = "daemon.newServer"
	if err := conf.validate(); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	s := &cacheServer{
		conf:         &conf,
		info:         make(map[string]string),
		infoKeys:     make([]string, 0, 20),
		tickerWg:     new(sync.WaitGroup),
		shutdownOnce: new(sync.Once),
	}
	return s, nil
}

func (s *cacheServer) shutdown() error {
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
		if s.eventer != nil {
			if err := s.eventer.FlushNodes(context.Background()); err != nil {
				shutdownErr = fmt.Errorf("error flushing eventer nodes: %w", err)
				return
			}
		}
		return
	})
	return shutdownErr
}

// start will fire up the refresh goroutine and the caching API http server as a
// daemon.  The daemon bits are included so it's easy for CLI cmds to start the
// a cache server
func (s *cacheServer) serve(ctx context.Context, cmd commander, l net.Listener) error {
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

	s.printInfo(s.conf.ui)

	{
		// If we have a persona information already, add it to the repository immediately so it can start
		// get updated.
		client, err := cmd.Client()
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		repo, err := cache.NewRepository(ctx, s.store)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		krType, tokName, err := cmd.DiscoverKeyringTokenInfo()
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		at := cmd.ReadTokenFromKeyring(krType, tokName)
		if at != nil {
			err := repo.AddPersona(ctx, &cache.Persona{
				KeyringType:  krType,
				TokenName:    tokName,
				BoundaryAddr: client.Addr(),
				AuthTokenId:  at.Id,
			})
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
		}
	}

	tic, err := newRefreshTicker(ctx, s.conf.refreshIntervalSeconds, s.store, cmd.ReadTokenFromKeyring)
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
	searchTargetsFn, err := newSearchTargetsHandlerFunc(ctx, s.store)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	mux.HandleFunc("/v1/search", searchTargetsFn)

	personaFn, err := newPersonaHandlerFunc(ctx, s.store, cmd, tic)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	mux.HandleFunc("/v1/personas", personaFn)

	s.httpSrv = &http.Server{
		Handler: mux,
	}
	if err = s.httpSrv.Serve(l); err != nil && err != http.ErrServerClosed && !errors.Is(err, net.ErrClosed) {
		event.WriteSysEvent(ctx, op, "error closing server", "err", err.Error())
	}
	cancel()
	tickerWg.Wait()

	return nil
}

func (s *cacheServer) printInfo(ui cli.Ui) {
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
	ui.Output("==> cache configuration:\n")
	for _, k := range s.infoKeys {
		ui.Output(fmt.Sprintf(
			"%s%s: %s",
			strings.Repeat(" ", padding-len(k)),
			strings.Title(k),
			s.info[k]))
	}
	ui.Output("")

	// Output the header that the server has started
	ui.Output("==> cache started! Log data will stream in below:\n")
}

func (s *cacheServer) setupLogging(ctx context.Context, w io.Writer) error {
	const op = "daemon.(Command).setupLogging"
	switch {
	case util.IsNil(w):
		return errors.New(ctx, errors.InvalidParameter, op, "log writer is nil")
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

	logFormat := logging.StandardFormat
	if s.conf.flagLogFormat != "" {
		var err error
		logFormat, err = logging.ParseLogFormat(s.conf.flagLogFormat)
		if err != nil {
			return fmt.Errorf("%s: %w", op, err)
		}
	}

	var logLock sync.Mutex
	s.logger = hclog.New(&hclog.LoggerOptions{
		Output:     gatedwriter.NewWriter(w),
		Level:      level,
		JSONFormat: logFormat == logging.JSONFormat,
		Mutex:      &logLock,
	})
	if err := event.InitFallbackLogger(s.logger); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	s.info["log level"] = level.String()
	s.infoKeys = append(s.infoKeys, "log level")
	s.info["log format"] = logFormat.String()
	s.infoKeys = append(s.infoKeys, "log format")

	var err error
	if s.eventer, err = setupEventing(ctx, s.logger, &logLock, logFormat); err != nil {
		return errors.Wrap(ctx, err, op)
	}

	return nil
}

func setupEventing(ctx context.Context, logger hclog.Logger, serializationLock *sync.Mutex, logFormat logging.LogFormat) (*event.Eventer, error) {
	const op = "daemon.setupEventing"
	switch {
	case util.IsNil(logger):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "logger is missing")
	case util.IsNil(serializationLock):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "serialization lock is missing")
	}
	serverName, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("%s: unable to determine hostname: %w", op, err)
	}
	serverName = fmt.Sprintf("%s/%s", serverName, "cache")

	var sinkFormat event.SinkFormat
	switch logFormat {
	case logging.JSONFormat:
		sinkFormat = event.JSONSinkFormat
	default:
		sinkFormat = event.TextHclogSinkFormat
	}

	cfg := &event.EventerConfig{
		AuditEnabled:        false,
		ObservationsEnabled: true,
		SysEventsEnabled:    true,
		Sinks: []*event.SinkConfig{
			{
				Name:       "default",
				EventTypes: []event.Type{event.EveryType},
				Format:     sinkFormat,
				Type:       event.StderrSink,
			},
		},
	}

	e, err := event.NewEventer(
		logger,
		serializationLock,
		serverName,
		*cfg)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create eventer"))
	}
	if err := event.InitSysEventer(logger, serializationLock, serverName, event.WithEventer(e)); err != nil {
		return nil, fmt.Errorf("%s: unable to initialize system eventer: %w", op, err)
	}
	return e, nil
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
