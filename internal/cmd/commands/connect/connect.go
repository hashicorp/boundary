// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package connect

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/proxy"
	targetspb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/targets"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/go-secure-stdlib/base62"
	"github.com/mitchellh/cli"
	"github.com/mr-tron/base58"
	"github.com/posener/complete"
	"go.uber.org/atomic"
	exec "golang.org/x/sys/execabs"
	"google.golang.org/protobuf/proto"
	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wspb"
)

const sessionCancelTimeout = 10 * time.Second

type SessionInfo struct {
	Address         string                       `json:"address"`
	Port            int                          `json:"port"`
	Protocol        string                       `json:"protocol"`
	Expiration      time.Time                    `json:"expiration"`
	ConnectionLimit int32                        `json:"connection_limit"`
	SessionId       string                       `json:"session_id"`
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

	sessionAuthz     *targets.SessionAuthorization
	sessionAuthzData *targetspb.SessionAuthorizationData

	connWg             *sync.WaitGroup
	listenerCloseOnce  sync.Once
	listener           *net.TCPListener
	listenerAddr       *net.TCPAddr
	connsLeftCh        chan int32
	connectionsLeft    *atomic.Int32
	expiration         time.Time
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

	tofuToken, err := base62.Random(20)
	if err != nil {
		c.PrintCliError(fmt.Errorf("Could not derive random bytes for tofu token: %w", err))
		return base.CommandCliError
	}

	c.connectionsLeft = atomic.NewInt32(0)
	c.connsLeftCh = make(chan int32)

	if c.flagListenAddr == "" {
		c.flagListenAddr = "127.0.0.1"
	}
	listenAddr := net.ParseIP(c.flagListenAddr)
	if listenAddr == nil {
		c.PrintCliError(fmt.Errorf("Could not successfully parse listen address of %s", c.flagListenAddr))
		return base.CommandUserError
	}

	authzString := c.flagAuthzToken
	switch {
	case authzString != "":
		if authzString == "-" {
			authBytes, err := ioutil.ReadAll(os.Stdin)
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
			c.sessionAuthz = new(targets.SessionAuthorization)
			if err := json.Unmarshal([]byte(authzString), c.sessionAuthz); err == nil {
				authzString = c.sessionAuthz.AuthorizationToken
			}
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
		c.sessionAuthz = sar.GetItem().(*targets.SessionAuthorization)
		authzString = c.sessionAuthz.AuthorizationToken
	}

	marshaled, err := base58.FastBase58Decoding(authzString)
	if err != nil {
		c.PrintCliError(fmt.Errorf("Unable to base58-decode authorization data: %w", err))
		return base.CommandUserError
	}
	if len(marshaled) == 0 {
		c.PrintCliError(errors.New("Zero length authorization information after decoding"))
		return base.CommandUserError
	}

	c.sessionAuthzData = new(targetspb.SessionAuthorizationData)
	if err := proto.Unmarshal(marshaled, c.sessionAuthzData); err != nil {
		c.PrintCliError(fmt.Errorf("Unable to proto-decode authorization data: %w", err))
		return base.CommandUserError
	}

	if len(c.sessionAuthzData.GetWorkerInfo()) == 0 {
		c.PrintCliError(errors.New("No workers found in authorization string"))
		return base.CommandUserError
	}

	if c.flagListenPort == 0 {
		c.flagListenPort = int(c.sessionAuthzData.DefaultClientPort)
	}

	c.connectionsLeft.Store(c.sessionAuthzData.ConnectionLimit)
	workerAddr := c.sessionAuthzData.GetWorkerInfo()[0].GetAddress()
	workerHost, _, err := net.SplitHostPort(workerAddr)
	if err != nil {
		if strings.Contains(err.Error(), "missing port") {
			workerHost = workerAddr
		} else {
			c.PrintCliError(fmt.Errorf("Error splitting worker adddress host/port: %w", err))
			return base.CommandUserError
		}
	}

	tlsConf, err := ClientTlsConfig(c.sessionAuthzData, workerHost)
	if err != nil {
		c.PrintCliError(fmt.Errorf("Error creating TLS configuration: %w", err))
		return base.CommandCliError
	}
	c.expiration = tlsConf.Certificates[0].Leaf.NotAfter

	// We don't _rely_ on client-side timeout verification but this prevents us
	// seeming to be ready for a connection that will immediately fail when we
	// try to actually make it
	c.proxyCtx, c.proxyCancel = context.WithDeadline(c.Context, c.expiration)
	defer c.proxyCancel()

	transport := cleanhttp.DefaultTransport()
	transport.DisableKeepAlives = false
	// This isn't/shouldn't used anyways really because the connection is
	// hijacked, just setting for completeness
	transport.IdleConnTimeout = 0
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := &tls.Dialer{Config: tlsConf}
		return dialer.DialContext(ctx, network, addr)
	}

	c.listener, err = net.ListenTCP("tcp", &net.TCPAddr{
		IP:   listenAddr,
		Port: c.flagListenPort,
	})
	if err != nil {
		c.PrintCliError(fmt.Errorf("Error starting listening port: %w", err))
		return base.CommandCliError
	}

	listenerCloseFunc := func() {
		// Forces the for loop to exist instead of spinning on errors
		c.connectionsLeft.Store(0)
		if err := c.listener.Close(); err != nil {
			c.PrintCliError(fmt.Errorf("Error closing listener on shutdown: %w", err))
			retCode = 2
		}
	}

	// Ensure it runs on any other return condition
	defer func() {
		c.listenerCloseOnce.Do(listenerCloseFunc)
	}()

	c.listenerAddr = c.listener.Addr().(*net.TCPAddr)

	if c.Func == "connect" {
		// "connect" indicates there is no subcommand to the connect function.
		// The only way a user will be able to connect to the session is by
		// connecting directly to the port and address we report to them here.

		var creds []*targets.SessionCredential
		if c.sessionAuthz != nil && len(c.sessionAuthz.Credentials) > 0 {
			creds = c.sessionAuthz.Credentials
		}

		sessInfo := SessionInfo{
			Protocol:        c.sessionAuthzData.GetType(),
			Address:         c.listenerAddr.IP.String(),
			Port:            c.listenerAddr.Port,
			Expiration:      c.expiration,
			ConnectionLimit: c.sessionAuthzData.GetConnectionLimit(),
			SessionId:       c.sessionAuthzData.GetSessionId(),
			Credentials:     creds,
		}
		switch base.Format(c.UI) {
		case "table":
			c.UI.Output(generateSessionInfoTableOutput(sessInfo))
		case "json":
			out, err := json.Marshal(&sessInfo)
			if err != nil {
				c.PrintCliError(fmt.Errorf("error marshaling session information: %w", err))
				return base.CommandCliError
			}
			c.UI.Output(string(out))
		}
	}

	c.connWg = new(sync.WaitGroup)

	c.connWg.Add(1)
	go func() {
		defer c.connWg.Done()
		for {
			listeningConn, err := c.listener.AcceptTCP()
			if err != nil {
				select {
				case <-c.proxyCtx.Done():
					return
				case <-c.Context.Done():
					return
				default:
					// When this hits zero we trigger listener close so this
					// isn't actually an error condition
					if c.connectionsLeft.Load() == 0 {
						return
					}
					c.PrintCliError(fmt.Errorf("Error accepting connection: %w", err))
					continue
				}
			}
			c.connWg.Add(1)
			go func() {
				defer listeningConn.Close()
				defer c.connWg.Done()
				wsConn, err := c.getWsConn(
					c.proxyCtx,
					workerAddr,
					transport)
				if err != nil {
					c.PrintCliError(err)
				} else {
					if err := c.runTcpProxyV1(wsConn, listeningConn, tofuToken); err != nil {
						c.PrintCliError(err)
					}
				}
			}()
		}
	}()

	timer := time.NewTimer(time.Until(c.expiration))
	c.connWg.Add(1)
	go func() {
		defer c.connWg.Done()
		defer c.listenerCloseOnce.Do(listenerCloseFunc)

		for {
			select {
			case <-c.proxyCtx.Done():
				timer.Stop()
				return
			case <-c.Context.Done():
				timer.Stop()
				return
			case <-timer.C:
				return
			case connsLeft := <-c.connsLeftCh:
				c.updateConnsLeft(connsLeft)
				if connsLeft == 0 {
					return
				}
			}
		}
	}()

	if c.flagExec != "" {
		c.connWg.Add(1)
		c.execCmdReturnValue = atomic.NewInt32(0)
		go c.handleExec(passthroughArgs)
	}

	c.connWg.Wait()

	if c.execCmdReturnValue != nil {
		retCode = int(c.execCmdReturnValue.Load())
	}

	termInfo := TerminationInfo{Reason: "Unknown"}
	sendSessionCancel := false
	select {
	case <-c.Context.Done():
		termInfo.Reason = "Received shutdown signal"
		sendSessionCancel = true
	default:
		if c.execCmdReturnValue != nil {
			// Don't print out in this case, so ensure we clear it
			termInfo.Reason = ""
			sendSessionCancel = true
		} else if !timer.Stop() {
			termInfo.Reason = "Session has expired"
		} else {
			if c.connectionsLeft.Load() == 0 {
				termInfo.Reason = "No connections left in session"
			}
		}
	}

	// Only send it if we should, and also if we're not after expiration, with a
	// bit of buffer in case clocks are not quite the same between worker and
	// this machine.
	if sendSessionCancel && time.Now().Before(c.expiration.Add(-5*time.Minute)) {
		ctx, cancel := context.WithTimeout(context.Background(), sessionCancelTimeout)
		wsConn, err := c.getWsConn(ctx, workerAddr, transport)
		if err != nil {
			c.PrintCliError(fmt.Errorf("error fetching connection to send session teardown request to worker: %w", err))
		} else {
			if err := c.sendSessionTeardown(ctx, wsConn, tofuToken); err != nil {
				c.PrintCliError(fmt.Errorf("error sending session teardown request to worker: %w", err))
			}
		}
		cancel()
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
				c.PrintCliError(fmt.Errorf("error marshaling termination information: %w", err))
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
			return fmt.Errorf("error marshaling credential information: %w", err)
		}
		c.UI.Output(string(out))
	}
	return nil
}

func (c *Command) getWsConn(
	ctx context.Context,
	workerAddr string,
	transport *http.Transport,
) (*websocket.Conn, error) {
	conn, resp, err := websocket.Dial(
		ctx,
		fmt.Sprintf("ws://%s/v1/proxy", workerAddr),
		&websocket.DialOptions{
			HTTPClient: &http.Client{
				Transport: transport,
			},
			Subprotocols: []string{globals.TcpProxyV1},
		},
	)
	if err != nil {
		switch {
		case strings.Contains(err.Error(), "tls: internal error"):
			return nil, errors.New("Session credentials were not accepted, or session is unauthorized")
		case strings.Contains(err.Error(), "connect: connection refused"):
			return nil, fmt.Errorf("Unable to connect to worker at %s", workerAddr)
		default:
			return nil, fmt.Errorf("Error dialing the worker: %w", err)
		}
	}

	if resp == nil {
		return nil, errors.New("Response from worker is nil")
	}
	if resp.Header == nil {
		return nil, errors.New("Response header is nil")
	}
	negProto := resp.Header.Get("Sec-WebSocket-Protocol")
	if negProto != globals.TcpProxyV1 {
		return nil, fmt.Errorf("Unexpected negotiated protocol: %s", negProto)
	}
	return conn, nil
}

func (c *Command) sendSessionTeardown(
	ctx context.Context,
	wsConn *websocket.Conn,
	tofuToken string,
) error {
	handshake := proxy.ClientHandshake{
		TofuToken: tofuToken,
		Command:   proxy.HANDSHAKECOMMAND_HANDSHAKECOMMAND_SESSION_CANCEL,
	}
	if err := wspb.Write(ctx, wsConn, &handshake); err != nil {
		return fmt.Errorf("error sending teardown handshake to worker: %w", err)
	}

	return nil
}

func (c *Command) runTcpProxyV1(
	wsConn *websocket.Conn,
	listeningConn *net.TCPConn,
	tofuToken string,
) error {
	handshake := proxy.ClientHandshake{TofuToken: tofuToken}
	if err := wspb.Write(c.proxyCtx, wsConn, &handshake); err != nil {
		return fmt.Errorf("error sending handshake to worker: %w", err)
	}
	var handshakeResult proxy.HandshakeResult
	if err := wspb.Read(c.proxyCtx, wsConn, &handshakeResult); err != nil {
		switch {
		case strings.Contains(err.Error(), "unable to authorize connection"):
			// There's no reason to think we'd be able to authorize any more
			// connections after the first has failed
			c.connsLeftCh <- 0
			return errors.New("Unable to authorize connection")
		}
		switch {
		case strings.Contains(err.Error(), "tofu token not allowed"):
			// Nothing will be able to be done here, so cancel the context too
			c.proxyCancel()
			return errors.New("Session token has already been used")
		default:
			return fmt.Errorf("error reading handshake result: %w", err)
		}
	}

	if handshakeResult.GetConnectionsLeft() != -1 {
		c.connsLeftCh <- handshakeResult.GetConnectionsLeft()
	}

	// Get a wrapped net.Conn so we can use io.Copy
	netConn := websocket.NetConn(c.proxyCtx, wsConn, websocket.MessageBinary)

	localWg := new(sync.WaitGroup)
	localWg.Add(2)

	go func() {
		defer localWg.Done()
		io.Copy(netConn, listeningConn)
		netConn.Close()
		listeningConn.Close()
	}()
	go func() {
		defer localWg.Done()
		io.Copy(listeningConn, netConn)
		listeningConn.Close()
		netConn.Close()
	}()
	localWg.Wait()

	return nil
}

func (c *Command) updateConnsLeft(connsLeft int32) {
	c.connectionsLeft.Store(connsLeft)

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
				c.PrintCliError(fmt.Errorf("error marshaling connection information: %w", err))
			}
			c.UI.Output(string(out))
		}
	}
}

func (c *Command) handleExec(passthroughArgs []string) {
	defer c.connWg.Done()
	defer c.proxyCancel()

	port := strconv.Itoa(c.listenerAddr.Port)
	ip := c.listenerAddr.IP.String()
	addr := c.listenerAddr.String()

	var args []string
	var envs []string
	var argsErr error

	var creds credentials
	if c.sessionAuthz != nil {
		var err error
		creds, err = parseCredentials(c.sessionAuthz.Credentials)
		if err != nil {
			c.PrintCliError(fmt.Errorf("Error interpreting secret: %w", err))
			c.execCmdReturnValue.Store(int32(3))
			return
		}
	}

	switch c.Func {
	case "http":
		httpArgs, err := c.httpFlags.buildArgs(c, port, ip, addr)
		if err != nil {
			c.PrintCliError(fmt.Errorf("Error parsing session args: %w", err))
			c.execCmdReturnValue.Store(int32(3))
			return
		}
		args = append(args, httpArgs...)

	case "postgres":
		pgArgs, pgEnvs, pgCreds, pgErr := c.postgresFlags.buildArgs(c, port, ip, addr, creds)
		if pgErr != nil {
			argsErr = pgErr
			break
		}
		args = append(args, pgArgs...)
		envs = append(envs, pgEnvs...)
		creds = pgCreds

	case "rdp":
		args = append(args, c.rdpFlags.buildArgs(c, port, ip, addr)...)

	case "ssh":
		sshArgs, sshEnvs, sshCreds, sshErr := c.sshFlags.buildArgs(c, port, ip, addr, creds)
		if sshErr != nil {
			argsErr = sshErr
			break
		}
		args = append(args, sshArgs...)
		envs = append(envs, sshEnvs...)
		creds = sshCreds

	case "kube":
		kubeArgs, err := c.kubeFlags.buildArgs(c, port, ip, addr)
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

	if err := c.printCredentials(creds.unconsumedSessionCredentials()); err != nil {
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
		args[i] = stringReplacer(args[i], "ip", ip)
		args[i] = stringReplacer(args[i], "addr", addr)
	}

	// NOTE: exec.CommandContext is a hard kill, so if used it leaves the
	// terminal in a weird state. It suffices to simply close the connection,
	// which already happens, so we don't need/want CommandContext here.
	cmd := exec.Command(c.flagExec, args...)
	// Add original and network related envs here
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("BOUNDARY_PROXIED_PORT=%s", port),
		fmt.Sprintf("BOUNDARY_PROXIED_IP=%s", ip),
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
