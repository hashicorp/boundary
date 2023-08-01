// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/base/logging"
	"github.com/hashicorp/boundary/internal/daemon/cache"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/boundary/internal/util"
	"github.com/hashicorp/boundary/version"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/gatedwriter"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/mitchellh/cli"
	"github.com/mitchellh/go-homedir"
	"github.com/mitchellh/go-ps"
	"github.com/sevlyar/go-daemon"
)

const (
	dotDirectoryNameTemplate = "%s/.boundary"
	pidFileNameTemplate      = "%s/.boundary/cache.pid"
	logFileNameTemplate      = "%s/.boundary/cache.log"
)

type commander interface {
	DiscoverKeyringTokenInfo() (string, string, error)
	Client(opt ...base.Option) (*api.Client, error)
}

type server struct {
	conf *serverConfig

	repository *cache.Repository

	infoKeys    []string
	info        map[string]string
	logger      hclog.Logger
	stderrLock  *sync.Mutex
	eventer     *event.Eventer
	logOutput   io.Writer
	gatedWriter *gatedwriter.Writer

	storeUrl string
	store    *cache.Store

	tickerWg *sync.WaitGroup
	httpSrv  *http.Server
	listener net.Listener

	shutdownOnce *sync.Once
}

type serverConfig struct {
	contextCancel          context.CancelFunc
	refreshIntervalSeconds int64
	cmd                    commander
	tokenName              string
	flagDatabaseUrl        string
	flagStoreDebug         bool
	flagLogLevel           string
	flagLogFormat          string
	flagSignal             string
	ui                     cli.Ui
}

func (sc *serverConfig) validate() error {
	return nil
}

// can be called before eventing is setup
func newServer(ctx context.Context, conf serverConfig) (*server, error) {
	const op = "daemon.(server).newServer"
	if err := conf.validate(); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	s := &server{
		conf:         &conf,
		stderrLock:   new(sync.Mutex),
		info:         make(map[string]string),
		infoKeys:     make([]string, 0, 20),
		tickerWg:     new(sync.WaitGroup),
		shutdownOnce: new(sync.Once),
	}
	return s, nil
}

func (s *server) shutdown() error {
	const op = "daemon.(server).Shutdown"

	var shutdownErr error
	s.shutdownOnce.Do(func() {
		if s.conf.contextCancel != nil {
			s.conf.contextCancel()
		}
		if err := s.listener.Close(); err != nil {
			shutdownErr = fmt.Errorf("error stopping listeners: %w", err)
			return
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
func (s *server) start(ctx context.Context, port uint) error {
	const op = "daemon.(server).start"
	switch {
	case util.IsNil(ctx):
		return errors.New(ctx, errors.InvalidParameter, op, "context is missing")
	case port == 0:
		return errors.New(ctx, errors.InvalidParameter, op, "port is missing")
	}

	homeDir, err := homedir.Dir()
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	pid, err := daemon.ReadPidFile(fmt.Sprintf(pidFileNameTemplate, homeDir))
	if err == nil {
		// we found a pid file
		proc, err := ps.FindProcess(pid)
		switch {
		case err != nil:
			return errors.Wrap(ctx, err, op)
		case proc != nil && s.conf.flagSignal == "":
			return errors.New(ctx, errors.Internal, op, fmt.Sprintf("cache daemon (pid %d) is already running.", proc.Pid()))
		}
	}

	// we need to do some daemon stuff right away in start-up
	done := make(chan struct{})
	var daemonCtx *daemon.Context
	{
		if err := os.MkdirAll(fmt.Sprintf(dotDirectoryNameTemplate, homeDir), os.ModePerm); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		daemonCtx = &daemon.Context{
			PidFileName: fmt.Sprintf(pidFileNameTemplate, homeDir),
			PidFilePerm: 0o644,
			LogFileName: fmt.Sprintf(logFileNameTemplate, homeDir),
			LogFilePerm: 0o640,
			WorkDir:     homeDir,
			Umask:       0o27,
		}

		termHandler := func(sig os.Signal) error {
			_ = s.shutdown()
			if sig == syscall.SIGQUIT {
				// we'll wait for a graceful shutdown to finish
				<-done
			}
			return daemon.ErrStop
		}
		daemon.AddCommand(daemon.StringFlag(&s.conf.flagSignal, "quit"), syscall.SIGQUIT, termHandler)
		daemon.AddCommand(daemon.StringFlag(&s.conf.flagSignal, "stop"), syscall.SIGTERM, termHandler)
		if len(daemon.ActiveFlags()) > 0 {
			d, err := daemonCtx.Search()
			if err != nil {
				log.Fatalf("Unable send signal to the daemon: %s", err.Error())
			}
			daemon.SendCommands(d)
			return nil
		}
	}
	// before we go too far, do we even have a token?
	client, err := s.conf.cmd.Client()
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if client.Token() == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing token")
	}

	// let's take care of things that might error, before we start
	// background bits
	var tic *refreshTicker
	{
		s.info["Listening port"] = strconv.FormatUint(uint64(port), 10)
		s.infoKeys = append(s.infoKeys, "Listening port")
		s.info["Store debug"] = strconv.FormatBool(s.conf.flagStoreDebug)
		s.infoKeys = append(s.infoKeys, "Store debug")

		logFormat, logLevel, err := s.setupLogging(s.conf.flagLogLevel, s.conf.flagLogFormat)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		s.info["log level"] = logLevel.String()
		s.infoKeys = append(s.infoKeys, "log level")
		s.info["log format"] = logFormat.String()
		s.infoKeys = append(s.infoKeys, "log format")

		if s.eventer, err = setupEventing(ctx, s.logger, s.stderrLock, logFormat); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		if s.store, s.storeUrl, err = openStore(ctx, s.conf.flagDatabaseUrl, s.conf.flagStoreDebug); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		s.info["Database URL"] = s.storeUrl
		s.infoKeys = append(s.infoKeys, "Database URL")

		mux := http.NewServeMux()
		searchTargetsFn, err := newSearchTargetsHandlerFunc(ctx, s.store, s.conf.tokenName)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		mux.HandleFunc("/v1/search/targets", searchTargetsFn)
		s.httpSrv = &http.Server{
			Handler: mux,
		}

		tic, err = newRefreshTicker(ctx, s.conf.refreshIntervalSeconds, s.conf.cmd, s.store, s.conf.tokenName)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		// TODO (jimlambrt 6/2023) - add mTLS here here and write client private key
		// and client cert in the key chain.

		s.listener, err = net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			log.Fatal("Listener error:", err)
		}
	}

	{
		// okay, we're ready to make this thing into a daemon
		d, err := daemonCtx.Reborn()
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		if d != nil {
			return nil
		}
		defer daemonCtx.Release()

		s.printInfo(s.conf.ui)

		s.tickerWg.Add(1)
		go func() {
			go func() {
				defer s.tickerWg.Done()
				tic.start(ctx)
			}()

			err = s.httpSrv.Serve(s.listener)
			if err != nil && err != http.ErrServerClosed && !errors.Is(err, net.ErrClosed) {
				event.WriteSysEvent(ctx, op, "error closing server", "err", err.Error())
			}
			done <- struct{}{}
		}()

		err = daemon.ServeSignals()
		if err != nil {
			log.Printf("Error: %s", err.Error())
		}

		event.WriteSysEvent(ctx, op, "daemon terminated")

		_ = s.shutdown()
	}
	return nil
}

const (
	filterKey = "filter"
	queryKey  = "query"

	idContainsKey          = "id_contains"
	nameContainsKey        = "name_contains"
	descriptionContainsKey = "description_contains"
	addressContainsKey     = "address_contains"

	idStartsWithKey          = "id_starts_with"
	nameStartsWithKey        = "name_starts_with"
	descriptionStartsWithKey = "description_starts_with"
	addressStartsWithKey     = "address_starts_with"

	idEndsWithKey          = "id_ends_with"
	nameEndsWithKey        = "name_ends_with"
	descriptionEndsWithKey = "description_ends_with"
	addressEndsWithKey     = "address_ends_with"
)

func newSearchTargetsHandlerFunc(ctx context.Context, store *cache.Store, tokenName string) (http.HandlerFunc, error) {
	const op = "daemon.newSearchTargetsHandlerFunc"
	switch {
	case util.IsNil(store):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "store is missing")
	case tokenName == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "token name is missing")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		filter, err := handlers.NewFilter(ctx, r.URL.Query().Get(filterKey))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		reqTokenName := r.Header.Get("token_name")
		if tokenName != reqTokenName {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		boundaryAddr := r.Header.Get("boundary_addr")

		// TODO: Look up the persona from fields passed in.  For now just hard code the addr and token.
		p := &cache.Persona{
			BoundaryAddr: boundaryAddr,
			TokenName:    reqTokenName,
		}

		repo, err := cache.NewRepository(ctx, store)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		var found []*targets.Target
		switch {
		case r.URL.Query().Get(queryKey) != "":
			found, err = repo.QueryTargets(r.Context(), p, r.URL.Query().Get(queryKey))
		default:
			found, err = repo.FindTargets(
				r.Context(),
				p,
				cache.WithIdContains(r.URL.Query().Get(idContainsKey)),
				cache.WithNameContains(r.URL.Query().Get(nameContainsKey)),
				cache.WithDescriptionContains(r.URL.Query().Get(descriptionContainsKey)),
				cache.WithAddressContains(r.URL.Query().Get(addressContainsKey)),

				cache.WithIdStartsWith(r.URL.Query().Get(idStartsWithKey)),
				cache.WithNameStartsWith(r.URL.Query().Get(nameStartsWithKey)),
				cache.WithDescriptionStartsWith(r.URL.Query().Get(descriptionStartsWithKey)),
				cache.WithAddressStartsWith(r.URL.Query().Get(addressStartsWithKey)),

				cache.WithIdEndsWith(r.URL.Query().Get(idEndsWithKey)),
				cache.WithNameEndsWith(r.URL.Query().Get(nameEndsWithKey)),
				cache.WithDescriptionEndsWith(r.URL.Query().Get(descriptionEndsWithKey)),
				cache.WithAddressEndsWith(r.URL.Query().Get(addressEndsWithKey)),
			)
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")

		finalItems := make([]*targets.Target, 0, len(found))
		for _, item := range found {
			if filter.Match(item) {
				finalItems = append(finalItems, item)
			}
		}

		items := struct {
			Items []*targets.Target `json:"items"`
		}{
			Items: finalItems,
		}
		j, err := json.Marshal(items)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(j)
	}, nil
}

func (s *server) printInfo(ui cli.Ui) {
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

func (s *server) setupLogging(flagLogLevel, flagLogFormat string) (logging.LogFormat, hclog.Level, error) {
	const op = "daemon.(Command).setupLogging"
	// flagLogLevel and flagLogFormat are still valid when empty

	s.logOutput = os.Stderr
	// s.logOutput = os.Stdout
	s.gatedWriter = gatedwriter.NewWriter(s.logOutput)

	logLevel := strings.ToLower(strings.TrimSpace(flagLogLevel))
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
		return logging.UnspecifiedFormat, hclog.NoLevel, fmt.Errorf("%s: unknown log level: %s", op, logLevel)
	}

	logFormat := logging.StandardFormat
	if flagLogFormat != "" {
		var err error
		logFormat, err = logging.ParseLogFormat(flagLogFormat)
		if err != nil {
			return logging.UnspecifiedFormat, hclog.NoLevel, fmt.Errorf("%s: %w", op, err)
		}
	}

	s.logger = hclog.New(&hclog.LoggerOptions{
		Output:     s.gatedWriter,
		Level:      level,
		JSONFormat: logFormat == logging.JSONFormat,
		Mutex:      s.stderrLock,
	})
	if err := event.InitFallbackLogger(s.logger); err != nil {
		return logging.UnspecifiedFormat, hclog.NoLevel, fmt.Errorf("%s: %w", op, err)
	}

	return logFormat, level, nil
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
