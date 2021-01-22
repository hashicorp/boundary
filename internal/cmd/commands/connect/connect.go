package connect

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
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
	targetspb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/targets"
	"github.com/hashicorp/boundary/internal/proxy"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/vault/sdk/helper/base62"
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
	Address         string    `json:"address"`
	Port            int       `json:"port"`
	Protocol        string    `json:"protocol"`
	Expiration      time.Time `json:"expiration"`
	ConnectionLimit int32     `json:"connection_limit"`
	SessionId       string    `json:"session_id"`
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

	sessionAuthzData *targetspb.SessionAuthorizationData

	connWg             *sync.WaitGroup
	listenerCloseOnce  sync.Once
	listener           *net.TCPListener
	listenerAddr       *net.TCPAddr
	connsLeftCh        chan int32
	connectionsLeft    atomic.Int32
	expiration         time.Time
	execCmdReturnValue *atomic.Int32
	proxyCtx           context.Context
	proxyCancel        context.CancelFunc
	outputJsonErrors   bool
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
			`      $ boundary connect -target-id ttcp_1234567890"`,
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
			fmt.Sprintf(`      $ boundary connect %s -target-id ttcp_1234567890"`, c.Func),
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

	f.BoolVar(&base.BoolVar{
		Name:       "output-json-errors",
		Target:     &c.outputJsonErrors,
		EnvVar:     "BOUNDARY_CONNECT_OUTPUT_JSON_ERRORS",
		Completion: complete.PredictNothing,
		Usage:      "Cause errors coming from this command to be output as JSON. This is experimental only and currently only meant for internal purposes. The format may change at any time and this flag/env var may be removed or modified at any time.",
		Hidden:     true,
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
		}
	}

	f := c.Flags()

	if err := f.Parse(args); err != nil {
		c.Error(err.Error())
		return 3
	}

	switch {
	case c.flagAuthzToken != "":
		switch {
		case c.flagTargetId != "":
			c.Error(`-target-id and -authz-token cannot both be specified`)
			return 3
		case c.flagTargetName != "":
			c.Error(`-target-name and -authz-token cannot both be specified`)
			return 3
		}
	default:
		if c.flagTargetId == "" &&
			(c.flagTargetName == "" ||
				(c.FlagScopeId == "" && c.FlagScopeName == "")) {
			c.Error("Target ID was not passed in, but no combination of target name and scope ID/name was passed in either")
			return 3
		}
		if c.flagTargetId != "" &&
			(c.flagTargetName != "" || c.FlagScopeId != "" || c.FlagScopeName != "") {
			c.Error("Cannot specify a target ID and also other lookup parameters")
			return 3
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
		c.Error(fmt.Errorf("Could not derive random bytes for tofu token: %w", err).Error())
		return 2
	}

	c.connsLeftCh = make(chan int32)

	if c.flagListenAddr == "" {
		c.flagListenAddr = "127.0.0.1"
	}
	listenAddr := net.ParseIP(c.flagListenAddr)
	if listenAddr == nil {
		c.Error(fmt.Sprintf("Could not successfully parse listen address of %s", c.flagListenAddr))
		return 3
	}

	authzString := c.flagAuthzToken
	switch {
	case authzString != "":
		if authzString == "-" {
			authBytes, err := ioutil.ReadAll(os.Stdin)
			if err != nil {
				c.Error(fmt.Errorf("No authorization string was provided and encountered the following error attempting to read it from stdin: %w", err).Error())
				return 3
			}
			if len(authBytes) == 0 {
				c.Error("No authorization data read from stdin")
				return 3
			}
			authzString = string(authBytes)
		}

		if authzString == "" {
			c.Error("Authorization data was empty")
			return 3
		}

		if authzString[0] == '{' {
			// Attempt to decode the JSON output of an authorize-session call
			// and pull the token out of there
			sessionAuthz := new(targets.SessionAuthorization)
			if err := json.Unmarshal([]byte(authzString), sessionAuthz); err == nil {
				authzString = sessionAuthz.AuthorizationToken
			}
		}

	default:
		client, err := c.Client()
		if err != nil {
			c.Error(fmt.Sprintf("Error creating API client: %s", err.Error()))
			return 2
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
				switch c.outputJsonErrors {
				case true:
					c.Error(apiErr.ResponseBody().String())
				default:
					c.Error(fmt.Sprintf("Error from controller when performing authorize-session against target: %s", base.PrintApiError(apiErr)))
				}
				return 1
			}
			c.Error(fmt.Sprintf("Error trying to authorize a session against target: %s", err.Error()))
			return 2
		}
		authzString = sar.GetItem().(*targets.SessionAuthorization).AuthorizationToken
	}

	marshaled, err := base58.FastBase58Decoding(authzString)
	if err != nil {
		c.Error(fmt.Errorf("Unable to base58-decode authorization data: %w", err).Error())
		return 3
	}
	if len(marshaled) == 0 {
		c.Error("Zero length authorization information after decoding")
		return 3
	}

	c.sessionAuthzData = new(targetspb.SessionAuthorizationData)
	if err := proto.Unmarshal(marshaled, c.sessionAuthzData); err != nil {
		c.Error(fmt.Errorf("Unable to proto-decode authorization data: %w", err).Error())
		return 3
	}

	if len(c.sessionAuthzData.GetWorkerInfo()) == 0 {
		c.Error("No workers found in authorization string")
		return 3
	}

	c.connectionsLeft.Store(c.sessionAuthzData.ConnectionLimit)
	workerAddr := c.sessionAuthzData.GetWorkerInfo()[0].GetAddress()

	parsedCert, err := x509.ParseCertificate(c.sessionAuthzData.Certificate)
	if err != nil {
		c.Error(fmt.Errorf("Unable to decode mTLS certificate: %w", err).Error())
		return 3
	}

	if len(parsedCert.DNSNames) != 1 {
		c.Error(fmt.Errorf("mTLS certificate has invalid parameters: %w", err).Error())
		return 3
	}

	c.expiration = parsedCert.NotAfter

	// We don't _rely_ on client-side timeout verification but this prevents us
	// seeming to be ready for a connection that will immediately fail when we
	// try to actually make it
	c.proxyCtx, c.proxyCancel = context.WithDeadline(c.Context, c.expiration)
	defer c.proxyCancel()

	certPool := x509.NewCertPool()
	certPool.AddCert(parsedCert)

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{c.sessionAuthzData.Certificate},
				PrivateKey:  ed25519.PrivateKey(c.sessionAuthzData.PrivateKey),
				Leaf:        parsedCert,
			},
		},
		RootCAs:    certPool,
		ServerName: parsedCert.DNSNames[0],
		MinVersion: tls.VersionTLS13,
	}

	transport := cleanhttp.DefaultTransport()
	transport.DisableKeepAlives = false
	transport.TLSClientConfig = tlsConf
	// This isn't/shouldn't used anyways really because the connection is
	// hijacked, just setting for completeness
	transport.IdleConnTimeout = 0

	c.listener, err = net.ListenTCP("tcp", &net.TCPAddr{
		IP:   listenAddr,
		Port: c.flagListenPort,
	})
	if err != nil {
		c.Error(fmt.Errorf("Error starting listening port: %w", err).Error())
		return 2
	}

	listenerCloseFunc := func() {
		// Forces the for loop to exist instead of spinning on errors
		c.connectionsLeft.Store(0)
		if err := c.listener.Close(); err != nil {
			c.Error(fmt.Errorf("Error closing listener on shutdown: %w", err).Error())
			retCode = 2
		}
	}

	// Ensure it runs on any other return condition
	defer func() {
		c.listenerCloseOnce.Do(listenerCloseFunc)
	}()

	c.listenerAddr = c.listener.Addr().(*net.TCPAddr)

	if c.flagExec == "" {
		sessInfo := SessionInfo{
			Protocol:        "tcp",
			Address:         c.listenerAddr.IP.String(),
			Port:            c.listenerAddr.Port,
			Expiration:      c.expiration,
			ConnectionLimit: c.sessionAuthzData.GetConnectionLimit(),
			SessionId:       c.sessionAuthzData.GetSessionId(),
		}

		switch base.Format(c.UI) {
		case "table":
			c.UI.Output(generateSessionInfoTableOutput(sessInfo))
		case "json":
			out, err := json.Marshal(&sessInfo)
			if err != nil {
				c.Error(fmt.Errorf("error marshaling session information: %w", err).Error())
				return 2
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
					c.Error(fmt.Errorf("Error accepting connection: %w", err).Error())
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
					c.Error(err.Error())
				} else {
					if err := c.runTcpProxyV1(wsConn, listeningConn, tofuToken); err != nil {
						c.Error(err.Error())
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
		c.execCmdReturnValue = new(atomic.Int32)
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
	case <-timer.C:
		termInfo.Reason = "Session has expired"
	default:
		if c.execCmdReturnValue != nil {
			// Don't print out in this case, so ensure we clear it
			termInfo.Reason = ""
			sendSessionCancel = true
		} else {
			if c.connectionsLeft.Load() == 0 {
				termInfo.Reason = "No connections left in session"
			}
		}
	}

	if sendSessionCancel {
		ctx, cancel := context.WithTimeout(context.Background(), sessionCancelTimeout)
		wsConn, err := c.getWsConn(ctx, workerAddr, transport)
		if err != nil {
			c.Error(fmt.Errorf("error fetching connection to send session teardown request to worker: %w", err).Error())
		} else {
			if err := c.sendSessionTeardown(ctx, wsConn, tofuToken); err != nil {
				c.Error(fmt.Errorf("error sending session teardown request to worker: %w", err).Error())
			}
		}
		cancel()
	}

	if termInfo.Reason != "" {
		switch base.Format(c.UI) {
		case "table":
			c.UI.Output(generateTerminationInfoTableOutput(termInfo))
		case "json":
			out, err := json.Marshal(&termInfo)
			if err != nil {
				c.Error(fmt.Errorf("error marshaling termination information: %w", err).Error())
				return 2
			}
			c.UI.Output(string(out))
		}
	}

	return
}

func (c *Command) getWsConn(
	ctx context.Context,
	workerAddr string,
	transport *http.Transport) (*websocket.Conn, error) {
	conn, resp, err := websocket.Dial(
		ctx,
		fmt.Sprintf("wss://%s/v1/proxy", workerAddr),
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
	tofuToken string) error {
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
	tofuToken string) error {
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
			return errors.New("Session is already in use")
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
				c.Error(fmt.Errorf("error marshaling connection information: %w", err).Error())
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

	switch c.Func {
	case "http":
		httpArgs, err := c.httpFlags.buildArgs(c, port, ip, addr)
		if err != nil {
			c.Error(fmt.Sprintf("Error parsing session args: %s", err))
			c.execCmdReturnValue.Store(int32(3))
			return
		}
		args = append(args, httpArgs...)

	case "postgres":
		args = append(args, c.postgresFlags.buildArgs(c, port, ip, addr)...)

	case "rdp":
		args = append(args, c.rdpFlags.buildArgs(c, port, ip, addr)...)

	case "ssh":
		args = append(args, c.sshFlags.buildArgs(c, port, ip, addr)...)

	case "kube":
		kubeArgs, err := c.kubeFlags.buildArgs(c, port, ip, addr)
		if err != nil {
			c.Error(fmt.Sprintf("Error parsing session args: %s", err))
			c.execCmdReturnValue.Store(int32(3))
			return
		}
		args = append(args, kubeArgs...)
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
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("BOUNDARY_PROXIED_PORT=%s", port),
		fmt.Sprintf("BOUNDARY_PROXIED_IP=%s", ip),
		fmt.Sprintf("BOUNDARY_PROXIED_ADDR=%s", addr),
	)
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

		c.Error(fmt.Sprintf("Failed to run command: %s", err))
		c.execCmdReturnValue.Store(int32(exitCode))
		return
	}
	c.execCmdReturnValue.Store(0)
}

func (c *Command) Error(err string) {
	switch c.outputJsonErrors {
	case true:
		c.UI.Error(fmt.Sprintf(`{"error": %q}`, err))
	default:
		c.UI.Error(err)
	}
}
