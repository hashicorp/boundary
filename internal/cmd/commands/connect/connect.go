// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package connect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/hashicorp/boundary/api"
	apiproxy "github.com/hashicorp/boundary/api/proxy"
	"github.com/hashicorp/boundary/api/sessions"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/util"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
	"go.uber.org/atomic"
	exec "golang.org/x/sys/execabs"
)

type SessionInfo struct {
	Address         string                       `json:"address"`
	Port            int                          `json:"port"`
	Protocol        string                       `json:"protocol"`
	Expiration      time.Time                    `json:"expiration"`
	ConnectionLimit int32                        `json:"connection_limit"`
	SessionId       string                       `json:"session_id"`
	Endpoint        string                       `json:"-"`
	Type            string                       `json:"-"`
	TargetId        string                       `json:"-"`
	HostId          string                       `json:"-"`
	Credentials     []*targets.SessionCredential `json:"credentials,omitempty"`
}

type ConnectionInfo struct {
	ConnectionsLeft int32 `json:"connections_left"`
}

type TerminationInfo struct {
	Reason string `json:"termination_reason"`
}

var (
	_ cli.Command             = (*Command)(nil)
	_ cli.CommandAutocomplete = (*Command)(nil)

	// rdpDefaultTimeout is the default inactivity timeout for boundary connect rdp
	// The default is zero (no timeout), however it is overridden for macOS clients only in connect_darwin.go
	rdpDefaultTimeout time.Duration = 0
)

type Command struct {
	*base.Command

	flagAuthzToken                    string
	flagListenAddr                    string
	flagListenPort                    int64
	flagTargetId                      string
	flagTargetName                    string
	flagHostId                        string
	flagExec                          string
	flagUsername                      string
	flagDbname                        string
	flagMongoDbAuthenticationDatabase string
	flagInactiveTimeout               time.Duration

	// HTTP
	httpFlags

	// Kube
	kubeFlags

	// Postgres
	postgresFlags

	// MySQL
	mysqlFlags

	// MongoDB
	mongoFlags

	// Cassandra
	cassandraFlags

	// Redis
	redisFlags

	// RDP
	rdpFlags

	// SSH
	sshFlags

	Func string

	sessInfo SessionInfo

	execCmdReturnValue *atomic.Int32
	proxyCtx           context.Context
	proxyCancel        context.CancelFunc
	outputJsonErrors   bool

	cleanupFuncs []func() error
}

func (c *Command) Synopsis() string {
	switch c.Func {
	case "connect":
		return "Connect to a target through a Boundary worker"
	case "http":
		return httpSynopsis
	case "postgres":
		return postgresSynopsis
	case "mysql":
		return mysqlSynopsis
	case "mongo":
		return mongoSynopsis
	case "cassandra":
		return cassandraSynopsis
	case "redis":
		return redisSynopsis
	case "rdp":
		return rdpSynopsis
	case "ssh":
		return sshSynopsis
	case "kube":
		return kubeSynopsis
	default:
		return ""
	}
}

func (c *Command) Help() string {
	switch c.Func {
	case "connect":
		return base.WrapForHelpText([]string{
			"Usage: boundary connect [options] [args]",
			"",
			`  This command performs a target authorization (or consumes an existing authorization token) and launches a proxied connection.`,
			"",
			"  Example:",
			"",
			`      $ boundary connect -target-id ttcp_1234567890`,
			"",
			"",
		}) + c.Flags().Help()

	default:
		return base.WrapForHelpText([]string{
			fmt.Sprintf("Usage: boundary connect %s [options] [args]", c.Func),
			"",
			fmt.Sprintf(`  This command performs a target authorization (or consumes an existing authorization token) and launches a proxied %s connection.`, c.Func),
			"",
			"  Example:",
			"",
			fmt.Sprintf(`      $ boundary connect %s -target-id ttcp_1234567890`, c.Func),
			"",
			"",
		}) + c.Flags().Help()
	}
}

func (c *Command) Flags() *base.FlagSets {
	set := c.FlagSet(base.FlagSetHTTP | base.FlagSetClient | base.FlagSetOutputFormat)
	f := set.NewFlagSet("Connect Options")

	f.StringVar(&base.StringVar{
		Name:       "authz-token",
		Target:     &c.flagAuthzToken,
		EnvVar:     "BOUNDARY_CONNECT_AUTHZ_TOKEN",
		Completion: complete.PredictNothing,
		Usage:      `Only needed if -target-id is not set. The authorization string returned from the Boundary controller via an "authorize-session" action against a target. If set to "-", the command will attempt to read in the authorization string from standard input.`,
	})

	f.StringVar(&base.StringVar{
		Name:   "target-id",
		Target: &c.flagTargetId,
		Usage:  "The ID of the target to authorize against. Cannot be used with -authz-token.",
	})

	f.StringVar(&base.StringVar{
		Name:   "host-id",
		Target: &c.flagHostId,
		Usage:  "The ID of a specific host to connect to out of the hosts from the target's host sets. If not specified, one is chosen at random.",
	})

	f.StringVar(&base.StringVar{
		Name:       "exec",
		Target:     &c.flagExec,
		EnvVar:     "BOUNDARY_CONNECT_EXEC",
		Completion: complete.PredictAnything,
		Usage:      `If set, after connecting to the worker, the given binary will be executed. This should be a binary on your path, or an absolute path. If all command flags are followed by " -- " (space, two hyphens, space), then any arguments after that will be sent directly to the binary.`,
	})

	f.StringVar(&base.StringVar{
		Name:   "target-name",
		Target: &c.flagTargetName,
		Usage:  "Target name, if authorizing the session via scope parameters and target name.",
	})

	f.StringVar(&base.StringVar{
		Name:       "target-scope-id",
		Target:     &c.FlagScopeId,
		EnvVar:     "BOUNDARY_CONNECT_TARGET_SCOPE_ID",
		Completion: complete.PredictAnything,
		Usage:      "Target scope ID, if authorizing the session via scope parameters and target name. Mutually exclusive with -scope-name.",
	})

	f.StringVar(&base.StringVar{
		Name:       "target-scope-name",
		Target:     &c.FlagScopeName,
		EnvVar:     "BOUNDARY_CONNECT_TARGET_SCOPE_NAME",
		Completion: complete.PredictAnything,
		Usage:      "Target scope name, if authorizing the session via scope parameters and target name. Mutually exclusive with -scope-id.",
	})

	f.DurationVar(&base.DurationVar{
		Name:       "inactive-timeout",
		Target:     &c.flagInactiveTimeout,
		Completion: complete.PredictAnything,
		Usage:      "How long to wait between connections before closing the session. Increase this value if the proxy closes during long-running processes, or use -1 to disable the timeout.",
	})

	switch c.Func {
	case "connect":
		f.StringVar(&base.StringVar{
			Name:       "listen-addr",
			Target:     &c.flagListenAddr,
			EnvVar:     "BOUNDARY_CONNECT_LISTEN_ADDR",
			Completion: complete.PredictAnything,
			Usage:      `If set, the CLI will attempt to bind its listening address to the given value, which must be an IP address. If it cannot, the command will error. If not set, defaults to the most common IPv4 loopback address (127.0.0.1).`,
		})

		f.Int64Var(&base.Int64Var{
			Name:       "listen-port",
			Target:     &c.flagListenPort,
			EnvVar:     "BOUNDARY_CONNECT_LISTEN_PORT",
			Completion: complete.PredictAnything,
			Usage:      `If set, the CLI will attempt to bind its listening port to the given value. If it cannot, the command will error.`,
		})

	case "http":
		httpOptions(c, set)

	case "postgres":
		postgresOptions(c, set)

	case "mysql":
		mysqlOptions(c, set)

	case "mongo":
		mongoOptions(c, set)

	case "cassandra":
		cassandraOptions(c, set)

	case "redis":
		redisOptions(c, set)

	case "rdp":
		rdpOptions(c, set)

	case "ssh":
		sshOptions(c, set)

	case "kube":
		kubeOptions(c, set)
	}

	return set
}

func (c *Command) AutocompleteArgs() complete.Predictor {
	return complete.PredictAnything
}

func (c *Command) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *Command) Run(args []string) (retCode int) {
	var passthroughArgs []string
	for i, v := range args {
		if v == "--" {
			passthroughArgs = args[i+1:]
			args = args[:i]
			break // only consider the first instance of '--' in the args list
		}
	}

	f := c.Flags()

	var alias string
	alias, args = base.ExtractAliasFromArgs(args)

	if err := f.Parse(args); err != nil {
		c.PrintCliError(err)
		return base.CommandUserError
	}

	if c.flagListenPort < 0 || c.flagListenPort > math.MaxUint16 {
		c.PrintCliError(errors.New("Invalid listen port supplied"))
		return base.CommandCliError
	}

	c.proxyCtx, c.proxyCancel = context.WithCancel(c.Context)
	defer c.proxyCancel()

	switch {
	case alias != "":
		if c.flagTargetId != "" && (c.flagTargetName != "" || c.FlagScopeId != "" || c.FlagScopeName != "") {
			c.PrintCliError(errors.New("Cannot specify a Target alias and also other lookup parameters"))
			return base.CommandUserError
		}
		c.flagTargetId = alias
	case c.flagAuthzToken != "":
		switch {
		case c.flagTargetId != "":
			c.PrintCliError(errors.New(`-target-id and -authz-token cannot both be specified`))
			return base.CommandUserError
		case c.flagTargetName != "":
			c.PrintCliError(errors.New(`-target-name and -authz-token cannot both be specified`))
			return base.CommandUserError
		}
	default:
		if c.flagTargetId == "" &&
			(c.flagTargetName == "" ||
				(c.FlagScopeId == "" && c.FlagScopeName == "")) {
			c.PrintCliError(errors.New("Target ID was not passed in, but no combination of target name and scope ID/name was passed in either"))
			return base.CommandUserError
		}
		if c.flagTargetId != "" &&
			(c.flagTargetName != "" || c.FlagScopeId != "" || c.FlagScopeName != "") {
			c.PrintCliError(errors.New("Cannot specify a target ID and also other lookup parameters"))
			return base.CommandUserError
		}
	}

	if c.flagExec == "" {
		switch c.Func {
		case "http":
			c.flagExec = c.httpFlags.defaultExec()
		case "ssh":
			c.flagExec = c.sshFlags.defaultExec()
		case "postgres":
			c.flagExec = c.postgresFlags.defaultExec()
		case "mysql":
			c.flagExec = c.mysqlFlags.defaultExec()
		case "mongo":
			c.flagExec = c.mongoFlags.defaultExec()
		case "cassandra":
			c.flagExec = c.cassandraFlags.defaultExec()
		case "redis":
			c.flagExec = c.redisFlags.defaultExec()
		case "rdp":
			c.flagExec = c.rdpFlags.defaultExec()
		case "kube":
			c.flagExec = c.kubeFlags.defaultExec()
		}
	}

	var addr netip.Addr
	if c.flagListenAddr == "" {
		c.flagListenAddr = "127.0.0.1"
	}
	addr, err := netip.ParseAddr(c.flagListenAddr)
	if err != nil {
		c.PrintCliError(fmt.Errorf("Error parsing listen address: %w", err))
		return base.CommandCliError
	}
	listenAddr := netip.AddrPortFrom(addr, uint16(c.flagListenPort))

	var clientProxy *apiproxy.ClientProxy

	authzString := c.flagAuthzToken
	switch {
	case authzString != "":
		if authzString == "-" {
			authBytes, err := io.ReadAll(os.Stdin)
			if err != nil {
				c.PrintCliError(fmt.Errorf("No authorization string was provided and encountered the following error attempting to read it from stdin: %w", err))
				return base.CommandUserError
			}
			if len(authBytes) == 0 {
				c.PrintCliError(errors.New("No authorization data read from stdin"))
				return base.CommandUserError
			}
			authzString = string(authBytes)
		}

		if authzString == "" {
			c.PrintCliError(errors.New("Authorization data was empty"))
			return base.CommandUserError
		}

		if authzString[0] == '{' {
			// Attempt to decode the JSON output of an authorize-session call
			// and pull the token out of there
			sa := new(targets.SessionAuthorization)
			if err := json.Unmarshal([]byte(authzString), sa); err == nil {
				authzString = sa.AuthorizationToken
			}
		}

		sad, err := targets.SessionAuthorization{AuthorizationToken: authzString}.GetSessionAuthorizationData()
		if err != nil {
			c.PrintCliError(fmt.Errorf("Error decoding session authorization data: %w", err))
			return base.CommandUserError
		}
		c.sessInfo = SessionInfo{
			Protocol:        sad.Type,
			ConnectionLimit: sad.ConnectionLimit,
			SessionId:       sad.SessionId,
			Endpoint:        sad.Endpoint,
			Type:            sad.Type,
			TargetId:        sad.TargetId,
			HostId:          sad.HostId,
		}

	default:
		client, err := c.Client()
		if c.WrapperCleanupFunc != nil {
			defer func() {
				if err := c.WrapperCleanupFunc(); err != nil {
					c.PrintCliError(fmt.Errorf("Error cleaning kms wrapper: %w", err))
				}
			}()
		}
		if err != nil {
			c.PrintCliError(fmt.Errorf("Error creating API client: %s", err))
			return base.CommandCliError
		}
		targetClient := targets.NewClient(client)

		var opts []targets.Option
		if len(c.flagHostId) != 0 {
			opts = append(opts, targets.WithHostId(c.flagHostId))
		}
		if len(c.flagTargetName) > 0 {
			opts = append(opts, targets.WithName(c.flagTargetName))
		}
		if len(c.FlagScopeId) > 0 {
			opts = append(opts, targets.WithScopeId(c.FlagScopeId))
		}
		if len(c.FlagScopeName) > 0 {
			opts = append(opts, targets.WithScopeName(c.FlagScopeName))
		}

		sar, err := targetClient.AuthorizeSession(c.Context, c.flagTargetId, opts...)
		if err != nil {
			if apiErr := api.AsServerError(err); apiErr != nil {
				c.PrintApiError(apiErr, "Error from controller when performing authorize-session action against given target")
				return base.CommandApiError
			}
			c.PrintCliError(fmt.Errorf("Error trying to authorize a session against target: %w", err))
			return base.CommandCliError
		}

		sa := sar.GetItem().(*targets.SessionAuthorization)
		c.sessInfo = SessionInfo{
			Protocol:        sa.Type,
			ConnectionLimit: sa.ConnectionLimit,
			SessionId:       sa.SessionId,
			Endpoint:        sa.Endpoint,
			Type:            sa.Type,
			TargetId:        sa.TargetId,
			HostId:          sa.HostId,
			Credentials:     sa.Credentials,
		}

		// the session was created specifically for this `boundary connect`
		// command, and should be closed as soon as the command has exited
		defer func() {
			var err error
			switch {
			case clientProxy != nil:
				err = clientProxy.CloseSession(0)
			default:
				// this is a weird special case. normally we let the client proxy end
				// the session, but it failed to be inited, so we need to create the
				// session client to ensure we don't leave hanging sessions
				sClient := sessions.NewClient(client)
				_, err = sClient.Cancel(c.Context, sa.SessionId, 0, sessions.WithAutomaticVersioning(true))
			}
			if err != nil {
				c.PrintCliError(fmt.Errorf("Error closing session after command end: %w", err))
			}
		}()

		authzString = sa.AuthorizationToken
	}

	connsLeftCh := make(chan int32)
	apiProxyOpts := []apiproxy.Option{apiproxy.WithConnectionsLeftCh(connsLeftCh)}
	if listenAddr.IsValid() {
		apiProxyOpts = append(apiProxyOpts, apiproxy.WithListenAddrPort(listenAddr))
	}
	clientProxy, err = apiproxy.New(
		c.proxyCtx,
		authzString,
		apiProxyOpts...,
	)
	if err != nil {
		c.PrintCliError(fmt.Errorf("Could not create client proxy: %w", err))
		return base.CommandCliError
	}
	c.sessInfo.Expiration = clientProxy.SessionExpiration()

	clientProxyCloseCh := make(chan struct{})
	connCountCloseCh := make(chan struct{})

	switch {
	case c.flagInactiveTimeout < 0:
		// timeout has been disabled, no need for option
	case c.flagInactiveTimeout == 0:
		// no timeout was specified, use protocol-specific defaults
		switch c.Func {
		case "rdp":
			apiProxyOpts = append(apiProxyOpts, apiproxy.WithInactivityTimeout(rdpDefaultTimeout))
		}
	default:
		// use provided timeout
		apiProxyOpts = append(apiProxyOpts, apiproxy.WithInactivityTimeout(c.flagInactiveTimeout))
	}

	proxyError := new(atomic.Error)
	go func() {
		defer close(clientProxyCloseCh)
		defer c.proxyCancel()
		if err = clientProxy.Start(apiProxyOpts...); err != nil {
			proxyError.Store(err)
		}
	}()
	go func() {
		defer close(connCountCloseCh)
		for {
			select {
			case <-c.proxyCtx.Done():
				// When the proxy exits it will cancel this even if we haven't
				// done it manually
				return
			case connsLeft := <-connsLeftCh:
				c.updateConnsLeft(connsLeft)
				if connsLeft == 0 {
					return
				}
			}
		}
	}()

	if c.Func == "connect" {
		// "connect" indicates there is no subcommand to the connect function.
		// The only way a user will be able to connect to the session is by
		// connecting directly to the port and address we report to them here.

		proxyAddr := clientProxy.ListenerAddress(c.proxyCtx)
		if proxyAddr == "" {
			if err := proxyError.Load(); err != nil {
				c.PrintCliError(fmt.Errorf("Error starting proxy: %w", err))
				return base.CommandCliError
			}
			c.PrintCliError(fmt.Errorf("Error starting proxy: no address returned"))
			return base.CommandCliError
		}
		var clientProxyHost, clientProxyPort string
		clientProxyHost, clientProxyPort, err = util.SplitHostPort(proxyAddr)
		if err != nil && !errors.Is(err, util.ErrMissingPort) {
			c.PrintCliError(fmt.Errorf("error splitting listener addr: %w", err))
			return base.CommandCliError
		}
		c.sessInfo.Address = clientProxyHost

		if clientProxyPort != "" {
			c.sessInfo.Port, err = strconv.Atoi(clientProxyPort)
			if err != nil {
				c.PrintCliError(fmt.Errorf("error parsing listener port: %w", err))
				return base.CommandCliError
			}
		}
		switch base.Format(c.UI) {
		case "table":
			c.UI.Output(generateSessionInfoTableOutput(c.sessInfo))
		case "json":
			out, err := json.Marshal(&c.sessInfo)
			if err != nil {
				c.PrintCliError(fmt.Errorf("error marshaling session information: %w", err))
				return base.CommandCliError
			}
			c.UI.Output(string(out))
		}
	}

	if c.flagExec != "" {
		c.execCmdReturnValue = atomic.NewInt32(0)
		c.handleExec(clientProxy, passthroughArgs)
	}

	<-connCountCloseCh
	<-clientProxyCloseCh

	if c.execCmdReturnValue != nil {
		retCode = int(c.execCmdReturnValue.Load())
	}

	termInfo := TerminationInfo{Reason: "Unknown"}
	select {
	case <-c.Context.Done():
		termInfo.Reason = "Received shutdown signal"
	default:
		if c.execCmdReturnValue != nil {
			// Don't print out in this case, so ensure we clear it
			termInfo.Reason = ""
		} else if r := clientProxy.CloseReason(); r != "" {
			termInfo.Reason = r
		} else if err := proxyError.Load(); err != nil {
			termInfo.Reason = "Error from proxy client: " + err.Error()
		}
	}

	for _, f := range c.cleanupFuncs {
		if err := f(); err != nil {
			c.PrintCliError(err)
		}
	}

	if termInfo.Reason != "" {
		switch base.Format(c.UI) {
		case "table":
			c.UI.Output(generateTerminationInfoTableOutput(termInfo))
		case "json":
			out, err := json.Marshal(&termInfo)
			if err != nil {
				c.PrintCliError(fmt.Errorf("Error marshaling termination information: %w", err))
				return base.CommandCliError
			}
			c.UI.Output(string(out))
		}
	}

	return retCode
}

func (c *Command) printCredentials(creds []*targets.SessionCredential) error {
	if len(creds) == 0 {
		return nil
	}
	switch base.Format(c.UI) {
	case "table":
		c.UI.Output(generateCredentialTableOutput(creds))
	case "json":
		out, err := json.Marshal(&struct {
			Credentials []*targets.SessionCredential `json:"credentials"`
		}{
			Credentials: creds,
		})
		if err != nil {
			return fmt.Errorf("Error marshaling credential information: %w", err)
		}
		c.UI.Output(string(out))
	}
	return nil
}

func (c *Command) updateConnsLeft(connsLeft int32) {
	connInfo := ConnectionInfo{
		ConnectionsLeft: connsLeft,
	}

	if c.flagExec == "" {
		switch base.Format(c.UI) {
		case "table":
			c.UI.Output(generateConnectionInfoTableOutput(connInfo))
		case "json":
			out, err := json.Marshal(&connInfo)
			if err != nil {
				c.PrintCliError(fmt.Errorf("Error marshaling connection information: %w", err))
			}
			c.UI.Output(string(out))
		}
	}
}

func (c *Command) handleExec(clientProxy *apiproxy.ClientProxy, passthroughArgs []string) {
	defer c.proxyCancel()

	addr := clientProxy.ListenerAddress(context.Background())
	var host, port string
	var err error
	host, port, err = util.SplitHostPort(addr)
	if err != nil && !errors.Is(err, util.ErrMissingPort) {
		c.PrintCliError(fmt.Errorf("Error splitting listener addr: %w", err))
		c.execCmdReturnValue.Store(int32(3))
		return
	}

	var args []string
	var envs []string
	var argsErr error

	var creds apiproxy.Credentials
	if len(c.sessInfo.Credentials) > 0 {
		var err error
		creds, err = apiproxy.ParseCredentials(c.sessInfo.Credentials)
		if err != nil {
			c.PrintCliError(fmt.Errorf("Error interpreting secret: %w", err))
			c.execCmdReturnValue.Store(int32(3))
			return
		}
	}

	switch c.Func {
	case "http":
		httpArgs, err := c.httpFlags.buildArgs(c, port, host, addr)
		if err != nil {
			c.PrintCliError(fmt.Errorf("Error parsing session args: %w", err))
			c.execCmdReturnValue.Store(int32(3))
			return
		}
		args = append(args, httpArgs...)

	case "postgres":
		pgArgs, pgEnvs, pgCreds, pgErr := c.postgresFlags.buildArgs(c, port, host, addr, creds)
		if pgErr != nil {
			argsErr = pgErr
			break
		}
		args = append(args, pgArgs...)
		envs = append(envs, pgEnvs...)
		creds = pgCreds

	case "mysql":
		mysqlArgs, mysqlEnvs, mysqlCreds, mysqlErr := c.mysqlFlags.buildArgs(c, port, host, addr, creds)
		if mysqlErr != nil {
			argsErr = mysqlErr
			break
		}
		args = append(args, mysqlArgs...)
		envs = append(envs, mysqlEnvs...)
		creds = mysqlCreds

	case "mongo":
		mongoArgs, mongoEnvs, mongoCreds, mongoErr := c.mongoFlags.buildArgs(c, port, host, addr, creds)
		if mongoErr != nil {
			argsErr = mongoErr
			break
		}
		args = append(args, mongoArgs...)
		envs = append(envs, mongoEnvs...)
		creds = mongoCreds

	case "cassandra":
		cassandraArgs, cassandraEnvs, cassandraCreds, cassandraErr := c.cassandraFlags.buildArgs(c, port, host, addr, creds)
		if cassandraErr != nil {
			argsErr = cassandraErr
			break
		}
		args = append(args, cassandraArgs...)
		envs = append(envs, cassandraEnvs...)
		creds = cassandraCreds

	case "redis":
		redisArgs, redisEnvs, redisCreds, redisErr := c.redisFlags.buildArgs(c, port, host, addr, creds)
		if redisErr != nil {
			argsErr = redisErr
			break
		}
		args = append(args, redisArgs...)
		envs = append(envs, redisEnvs...)
		creds = redisCreds

	case "rdp":
		args = append(args, c.rdpFlags.buildArgs(c, port, host, addr)...)

	case "ssh":
		sshArgs, sshEnvs, sshCreds, sshErr := c.sshFlags.buildArgs(c, port, host, addr, creds)
		if sshErr != nil {
			argsErr = sshErr
			break
		}
		args = append(args, sshArgs...)
		envs = append(envs, sshEnvs...)
		creds = sshCreds

	case "kube":
		kubeArgs, err := c.kubeFlags.buildArgs(c, port, host, addr)
		if err != nil {
			c.PrintCliError(fmt.Errorf("Error parsing session args: %w", err))
			c.execCmdReturnValue.Store(int32(3))
			return
		}
		args = append(args, kubeArgs...)
	}

	if argsErr != nil {
		c.PrintCliError(fmt.Errorf("Failed to collect args: %w", argsErr))
		c.execCmdReturnValue.Store(int32(2))
		return
	}

	if err := c.printCredentials(creds.UnconsumedSessionCredentials()); err != nil {
		c.PrintCliError(fmt.Errorf("Failed to print credentials: %w", err))
		c.execCmdReturnValue.Store(int32(2))
		return
	}

	args = append(passthroughArgs, args...)

	stringReplacer := func(in, typ, replacer string) string {
		for _, style := range []string{
			fmt.Sprintf("{{boundary.%s}}", typ),
			fmt.Sprintf("{{ boundary.%s}}", typ),
			fmt.Sprintf("{{boundary.%s }}", typ),
			fmt.Sprintf("{{ boundary.%s }}", typ),
		} {
			in = strings.Replace(in, style, replacer, -1)
		}
		return in
	}

	for i := range args {
		args[i] = stringReplacer(args[i], "port", port)
		args[i] = stringReplacer(args[i], "ip", host)
		args[i] = stringReplacer(args[i], "addr", addr)
	}

	// NOTE: exec.CommandContext is a hard kill, so if used it leaves the
	// terminal in a weird state. It suffices to simply close the connection,
	// which already happens, so we don't need/want CommandContext here.
	cmd := exec.Command(c.flagExec, args...)
	// Add original and network related envs here
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("BOUNDARY_PROXIED_PORT=%s", port),
		fmt.Sprintf("BOUNDARY_PROXIED_IP=%s", host),
		fmt.Sprintf("BOUNDARY_PROXIED_ADDR=%s", addr),
	)
	// Envs that came from subcommand handling
	cmd.Env = append(cmd.Env, envs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmdExit := make(chan struct{})

	cmdError := func(err error) {
		if exitError, ok := err.(*exec.ExitError); ok {
			if exitError.Success() {
				c.execCmdReturnValue.Store(0)
				return
			}
			if ws, ok := exitError.Sys().(syscall.WaitStatus); ok {
				c.execCmdReturnValue.Store(int32(ws.ExitStatus()))
				return
			}
		}

		c.PrintCliError(fmt.Errorf("Failed to run command: %w", err))
		c.execCmdReturnValue.Store(2)
		return
	}

	go func() {
		defer close(cmdExit)
		if err := cmd.Start(); err != nil {
			cmdError(err)
			return
		}
		if err := cmd.Wait(); err != nil {
			cmdError(err)
			return
		}
		c.execCmdReturnValue.Store(0)
	}()

	for {
		select {
		case <-c.proxyCtx.Done():
			// the proxy exited for some reason, end the cmd since connections are no longer possible
			_ = endProcess(cmd.Process)
		case <-cmdExit:
			return
		}
	}
}
