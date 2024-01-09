// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package connect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/hashicorp/boundary/api"
	apiproxy "github.com/hashicorp/boundary/api/proxy"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
	"go.uber.org/atomic"
	exec "golang.org/x/sys/execabs"
)

const sessionCancelTimeout = 10 * time.Second

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
)

type Command struct {
	*base.Command

	flagAuthzToken string
	flagListenAddr string
	flagListenPort int
	flagTargetId   string
	flagTargetName string
	flagHostId     string
	flagExec       string
	flagUsername   string
	flagDbname     string

	// HTTP
	httpFlags

	// Kube
	kubeFlags

	// Postgres
	postgresFlags

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

	switch c.Func {
	case "connect":
		f.StringVar(&base.StringVar{
			Name:       "listen-addr",
			Target:     &c.flagListenAddr,
			EnvVar:     "BOUNDARY_CONNECT_LISTEN_ADDR",
			Completion: complete.PredictAnything,
			Usage:      `If set, the CLI will attempt to bind its listening address to the given value, which must be an IP address. If it cannot, the command will error. If not set, defaults to the most common IPv4 loopback address (127.0.0.1).`,
		})

		f.IntVar(&base.IntVar{
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
		case "rdp":
			c.flagExec = c.rdpFlags.defaultExec()
		case "kube":
			c.flagExec = c.kubeFlags.defaultExec()
		}
	}

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
		authzString = sa.AuthorizationToken
	}

	var listenAddr netip.AddrPort
	var addr netip.Addr
	if c.flagListenAddr == "" {
		c.flagListenAddr = "127.0.0.1"
	}
	addr, err := netip.ParseAddr(c.flagListenAddr)
	if err != nil {
		c.PrintCliError(fmt.Errorf("Error parsing listen address: %w", err))
		return base.CommandCliError
	}
	listenAddr = netip.AddrPortFrom(addr, uint16(c.flagListenPort))

	connsLeftCh := make(chan int32)
	apiProxyOpts := []apiproxy.Option{apiproxy.WithConnectionsLeftCh(connsLeftCh)}
	if listenAddr.IsValid() {
		apiProxyOpts = append(apiProxyOpts, apiproxy.WithListenAddrPort(listenAddr))
	}
	clientProxy, err := apiproxy.New(
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

	proxyError := new(atomic.Error)
	go func() {
		defer close(clientProxyCloseCh)
		proxyError.Store(clientProxy.Start())
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

		proxyAddr := clientProxy.ListenerAddress(context.Background())
		var clientProxyHost, clientProxyPort string
		clientProxyHost, clientProxyPort, err = net.SplitHostPort(proxyAddr)
		if err != nil {
			if strings.Contains(err.Error(), "missing port") {
				clientProxyHost = proxyAddr
			} else {
				c.PrintCliError(fmt.Errorf("error splitting listener addr: %w", err))
				return base.CommandCliError
			}
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
		} else if time.Now().After(clientProxy.SessionExpiration()) {
			termInfo.Reason = "Session has expired"
		} else if clientProxy.ConnectionsLeft() == 0 {
			termInfo.Reason = "No connections left in session"
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

	return
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
	host, port, err = net.SplitHostPort(addr)
	if err != nil {
		if strings.Contains(err.Error(), "missing port") {
			host = addr
		} else {
			c.PrintCliError(fmt.Errorf("Error splitting listener addr: %w", err))
			c.execCmdReturnValue.Store(int32(3))
			return
		}
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

	if err := cmd.Run(); err != nil {
		exitCode := 2

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
		c.execCmdReturnValue.Store(int32(exitCode))
		return
	}
	c.execCmdReturnValue.Store(0)
}
