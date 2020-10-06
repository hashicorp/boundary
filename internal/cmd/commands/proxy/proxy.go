package proxy

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
	"os/exec"
	"runtime"
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
	"google.golang.org/protobuf/proto"
	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wspb"
)

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

var _ cli.Command = (*Command)(nil)
var _ cli.CommandAutocomplete = (*Command)(nil)

type Command struct {
	*base.Command

	flagAuthz      string
	flagListenAddr string
	flagListenPort int
	flagTargetId   string
	flagHostId     string
	flagExec       string
	flagUsername   string

	// HTTP
	flagHttpStyle  string
	flagHttpHost   string
	flagHttpPath   string
	flagHttpMethod string
	flagHttpScheme string

	// SSH
	flagSshStyle string

	// Postgres
	flagPostgresStyle string

	// RDP
	flagRdpStyle string

	Func string

	sessionAuthz *targets.SessionAuthorization

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
}

func (c *Command) Synopsis() string {
	switch c.Func {
	case "proxy":
		return "Launch the Boundary CLI in proxy mode"
	case "connect":
		return "Authorize a session against a target and launch a proxied connection"
	case "http":
		return "Authorize a session against a target and invoke an HTTP client to connect"
	case "ssh":
		return "Authorize a session against a target and invoke an SSH client to connect"
	case "postgres":
		return "Authorize a session against a target and invoke a Postgres client to connect"
	case "rdp":
		return "Authorize a session against a target and invoke an RDP client to connect"
	}
	return ""
}

func (c *Command) Help() string {
	switch c.Func {
	case "proxy":
		return base.WrapForHelpText([]string{
			"Usage: boundary proxy [options] [args]",
			"",
			"  This command allows launching the Boundary CLI in proxy mode. In this mode, the CLI expects to take in an authorization string returned from a Boundary controller. The CLI will then create a connection to a Boundary worker and ready a listening port for a local connection.",
			"",
			"  Example:",
			"",
			`      $ boundary proxy -auth "UgxzX29mVEpwNUt6QlGiAQ..."`,
		}) + c.Flags().Help()

	case "connect":
		return base.WrapForHelpText([]string{
			"Usage: boundary connect [options] [args]",
			"",
			`  This command performs a target authorization and proxy launch in one command; it is equivalent to sending the output of "boundary targets authorize-session" into "boundary proxy". See the help output for those commands for more information.`,
			"",
			"  Example:",
			"",
			`      $ boundary connect -target-id ttcp_1234567890"`,
		}) + c.Flags().Help()
	}
	return ""
}

func (c *Command) Flags() *base.FlagSets {
	bits := base.FlagSetOutputFormat
	if c.Func == "connect" {
		bits = base.FlagSetHTTP | base.FlagSetClient | bits
	}
	set := c.FlagSet(bits)

	switch c.Func {
	case "proxy":
		f := set.NewFlagSet("Proxy Options")

		f.StringVar(&base.StringVar{
			Name:       "authz",
			Target:     &c.flagAuthz,
			EnvVar:     "BOUNDARY_PROXY_AUTHZ",
			Completion: complete.PredictAnything,
			Usage:      `The authorization string returned from the Boundary controller. If set to "-", the command will attempt to read in the authorization string from standard input.`,
		})

		f.StringVar(&base.StringVar{
			Name:       "listen-addr",
			Target:     &c.flagListenAddr,
			EnvVar:     "BOUNDARY_PROXY_LISTEN_ADDR",
			Completion: complete.PredictAnything,
			Usage:      `If set, the CLI will attempt to bind its listening address to the given value, which must be an IP address. If it cannot, the command will error. If not set, defaults to the IPv4 loopback address (127.0.0.1).`,
		})

		f.IntVar(&base.IntVar{
			Name:       "listen-port",
			Target:     &c.flagListenPort,
			EnvVar:     "BOUNDARY_PROXY_LISTEN_PORT",
			Completion: complete.PredictAnything,
			Usage:      `If set, the CLI will attempt to bind its listening port to the given value. If it cannot, the command will error.`,
		})

	case "connect", "http", "ssh", "rdp", "postgres":
		f := set.NewFlagSet("Connect Options")

		f.StringVar(&base.StringVar{
			Name:   "target-id",
			Target: &c.flagTargetId,
			Usage:  "The ID of the target to authorize against.",
		})
		f.StringVar(&base.StringVar{
			Name:   "host-id",
			Target: &c.flagHostId,
			Usage:  "The ID of a specific host to connect to out of the hosts from the target's host sets. If not specified, one is chosen at random.",
		})

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

		f.StringVar(&base.StringVar{
			Name:       "exec",
			Target:     &c.flagExec,
			EnvVar:     "BOUNDARY_CONNECT_EXEC",
			Completion: complete.PredictAnything,
			Usage:      `If set, after connecting to the worker, the given binary will be executed. This should be a binary on your path, or an absolute path. If all command flags are followed by " -- " (space, two hyphens, space), then any arguments after that will be sent directly to the binary.`,
		})
	}

	switch c.Func {
	case "http":
		f := set.NewFlagSet("HTTP Options")

		f.StringVar(&base.StringVar{
			Name:       "style",
			Target:     &c.flagHttpStyle,
			EnvVar:     "BOUNDARY_CONNECT_HTTP_STYLE",
			Completion: complete.PredictSet("curl"),
			Default:    "curl",
			Usage:      `Specifies how the CLI will attempt to invoke an HTTP client. This will also set a suitable default for -exec if a value was not specified. Currently-understood values are "curl".`,
		})

		f.StringVar(&base.StringVar{
			Name:       "host",
			Target:     &c.flagHttpHost,
			EnvVar:     "BOUNDARY_CONNECT_HTTP_HOST",
			Completion: complete.PredictNothing,
			Usage:      `Specifies the host value to use. The specified hostname will be passed through to the client (if supported) for use in the Host header and TLS SNI value.`,
		})

		f.StringVar(&base.StringVar{
			Name:       "path",
			Target:     &c.flagHttpPath,
			EnvVar:     "BOUNDARY_CONNECT_HTTP_PATH",
			Completion: complete.PredictNothing,
			Usage:      `Specifies a path that will be appended to the generated URL.`,
		})

		f.StringVar(&base.StringVar{
			Name:       "method",
			Target:     &c.flagHttpMethod,
			EnvVar:     "BOUNDARY_CONNECT_HTTP_METHOD",
			Completion: complete.PredictNothing,
			Usage:      `Specifies the method to use. If not set, will use the client's default.`,
		})

		f.StringVar(&base.StringVar{
			Name:       "scheme",
			Target:     &c.flagHttpScheme,
			Default:    "https",
			EnvVar:     "BOUNDARY_CONNECT_HTTP_SCHEME",
			Completion: complete.PredictNothing,
			Usage:      `Specifies the scheme to use.`,
		})

	case "ssh":
		f := set.NewFlagSet("SSH Options")

		f.StringVar(&base.StringVar{
			Name:       "style",
			Target:     &c.flagSshStyle,
			EnvVar:     "BOUNDARY_CONNECT_SSH_STYLE",
			Completion: complete.PredictSet("ssh", "putty"),
			Default:    "ssh",
			Usage:      `Specifies how the CLI will attempt to invoke an SSH client. This will also set a suitable default for -exec if a value was not specified. Currently-understood values are "ssh" and "putty".`,
		})

		f.StringVar(&base.StringVar{
			Name:       "username",
			Target:     &c.flagUsername,
			EnvVar:     "BOUNDARY_CONNECT_USERNAME",
			Completion: complete.PredictNothing,
			Usage:      `Specifies the username to pass through to the client`,
		})

	case "postgres":
		f := set.NewFlagSet("Postgres Options")

		f.StringVar(&base.StringVar{
			Name:       "style",
			Target:     &c.flagPostgresStyle,
			EnvVar:     "BOUNDARY_CONNECT_POSTGRES_STYLE",
			Completion: complete.PredictSet("psql"),
			Default:    "psql",
			Usage:      `Specifies how the CLI will attempt to invoke a Postgres client. This will also set a suitable default for -exec if a value was not specified. Currently-understood values are "psql".`,
		})

		f.StringVar(&base.StringVar{
			Name:       "username",
			Target:     &c.flagUsername,
			EnvVar:     "BOUNDARY_CONNECT_USERNAME",
			Completion: complete.PredictNothing,
			Usage:      `Specifies the username to pass through to the client`,
		})

	case "rdp":
		f := set.NewFlagSet("RDP Options")

		f.StringVar(&base.StringVar{
			Name:       "style",
			Target:     &c.flagRdpStyle,
			EnvVar:     "BOUNDARY_CONNECT_RDP_STYLE",
			Completion: complete.PredictSet("mstsc", "open"),
			Usage:      `Specifies how the CLI will attempt to invoke an RDP client. This will also set a suitable default for -exec if a value was not specified. Currently-understood values are "mstsc", which is the default on Windows and launches the Windows client, and "open", which is the default on Mac and launches via an rdp:// URL.`,
		})
	}

	/*
		f.BoolVar(&base.BoolVar{
			Name:       "verbose",
			Target:     &c.flagVerbose,
			Completion: complete.PredictAnything,
			Usage:      "Turns on some extra verbosity in the command output.",
		})
	*/

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
		c.UI.Error(err.Error())
		return 1
	}

	switch c.Func {
	case "http":
		if c.flagExec == "" {
			c.flagExec = strings.ToLower(c.flagHttpStyle)
		}
	case "ssh":
		if c.flagExec == "" {
			c.flagExec = strings.ToLower(c.flagSshStyle)
		}
	case "postgres":
		if c.flagExec == "" {
			c.flagExec = strings.ToLower(c.flagPostgresStyle)
		}
	case "rdp":
		if c.flagExec == "" {
			c.flagRdpStyle = strings.ToLower(c.flagRdpStyle)
			switch c.flagRdpStyle {
			case "":
				switch runtime.GOOS {
				case "windows":
					c.flagRdpStyle = "mstsc"
				case "darwin":
					c.flagRdpStyle = "open"
				default:
					// We may want to support rdesktop and/or xfreerdp at some point soon
					c.flagRdpStyle = "mstsc"
				}
			}
			if c.flagRdpStyle == "mstsc" {
				c.flagRdpStyle = "mstsc.exe"
			}
			c.flagExec = c.flagRdpStyle
		}
	}

	tofuToken, err := base62.Random(20)
	if err != nil {
		c.UI.Error(fmt.Errorf("Could not derive random bytes for tofu token: %w", err).Error())
		return 1
	}

	c.connsLeftCh = make(chan int32)

	if c.flagListenAddr == "" {
		c.flagListenAddr = "127.0.0.1"
	}
	listenAddr := net.ParseIP(c.flagListenAddr)
	if listenAddr == nil {
		c.UI.Error(fmt.Sprintf("Could not successfully parse listen address of %s", c.flagListenAddr))
		return 1
	}

	authzString := c.flagAuthz
	switch c.Func {
	case "proxy":
		if authzString == "-" {
			authBytes, err := ioutil.ReadAll(os.Stdin)
			if err != nil {
				c.UI.Error(fmt.Errorf("No authorization string was provided and encountered the following error attempting to read it from stdin: %w", err).Error())
				return 1
			}
			if len(authBytes) == 0 {
				c.UI.Error("No authorization data read from stdin")
				return 1
			}
			authzString = string(authBytes)
		}

		if authzString == "" {
			c.UI.Error("Authorization data was empty")
			return 1
		}

		if authzString[0] == '{' {
			// Attempt to decode the JSON output of an authorize-session call
			// and pull the token out of there
			c.sessionAuthz = new(targets.SessionAuthorization)
			if err := json.Unmarshal([]byte(authzString), c.sessionAuthz); err == nil {
				authzString = c.sessionAuthz.AuthorizationToken
			}
		}

	case "connect", "http", "ssh", "postgres", "rdp":
		if c.flagTargetId == "" {
			c.UI.Error("Target ID must be provided")
			return 1
		}

		client, err := c.Client()
		if err != nil {
			c.UI.Error(fmt.Sprintf("Error creating API client: %s", err.Error()))
			return 2
		}
		targetClient := targets.NewClient(client)

		var opts []targets.Option
		if len(c.flagHostId) != 0 {
			opts = append(opts, targets.WithHostId(c.flagHostId))
		}

		sar, err := targetClient.AuthorizeSession(c.Context, c.flagTargetId, opts...)
		if err != nil {
			if api.AsServerError(err) != nil {
				c.UI.Error(fmt.Sprintf("Error from controller when performing authorize-session against target: %s", err.Error()))
				return 1
			}
			c.UI.Error(fmt.Sprintf("Error trying to authorize a session against target: %s", err.Error()))
			return 2
		}
		c.sessionAuthz = sar.GetItem().(*targets.SessionAuthorization)
		authzString = c.sessionAuthz.AuthorizationToken
	}

	marshaled, err := base58.FastBase58Decoding(authzString)
	if err != nil {
		c.UI.Error(fmt.Errorf("Unable to base58-decode authorization data: %w", err).Error())
		return 1
	}
	if len(marshaled) == 0 {
		c.UI.Error("Zero length authorization information after decoding")
		return 1
	}

	data := new(targetspb.SessionAuthorizationData)
	if err := proto.Unmarshal(marshaled, data); err != nil {
		c.UI.Error(fmt.Errorf("Unable to proto-decode authorization data: %w", err).Error())
		return 1
	}

	if len(data.GetWorkerInfo()) == 0 {
		c.UI.Error("No workers found in authorization string")
		return 1
	}

	c.connectionsLeft.Store(data.ConnectionLimit)
	workerAddr := data.GetWorkerInfo()[0].GetAddress()

	parsedCert, err := x509.ParseCertificate(data.Certificate)
	if err != nil {
		c.UI.Error(fmt.Errorf("Unable to decode mTLS certificate: %w", err).Error())
		return 1
	}

	if len(parsedCert.DNSNames) != 1 {
		c.UI.Error(fmt.Errorf("mTLS certificate has invalid parameters: %w", err).Error())
		return 1
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
				Certificate: [][]byte{data.Certificate},
				PrivateKey:  ed25519.PrivateKey(data.PrivateKey),
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
		c.UI.Error(fmt.Errorf("Error starting listening port: %w", err).Error())
		return 1
	}

	listenerCloseFunc := func() {
		// Forces the for loop to exist instead of spinning on errors
		c.connectionsLeft.Store(0)
		if err := c.listener.Close(); err != nil {
			c.UI.Error(fmt.Errorf("Error closing listener on shutdown: %w", err).Error())
			retCode = 1
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
			ConnectionLimit: data.GetConnectionLimit(),
			SessionId:       data.GetSessionId(),
		}

		switch base.Format(c.UI) {
		case "table":
			c.UI.Output(generateSessionInfoTableOutput(sessInfo))
		case "json":
			out, err := json.Marshal(&sessInfo)
			if err != nil {
				c.UI.Error(fmt.Errorf("error marshaling session information: %w", err).Error())
				return 1
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
					// When this hits zero we tigger listener close so this
					// isn't actually an error condition
					if c.connectionsLeft.Load() == 0 {
						return
					}
					c.UI.Error(fmt.Errorf("Error accepting connection: %w", err).Error())
					continue
				}
			}
			c.connWg.Add(1)
			go func() {
				defer listeningConn.Close()
				if err := c.handleConnection(
					listeningConn,
					workerAddr,
					tofuToken,
					transport); err != nil {
					c.UI.Error(err.Error())
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
	select {
	case <-c.Context.Done():
		termInfo.Reason = "Received shutdown signal"
	case <-timer.C:
		termInfo.Reason = "Session has expired"
	default:
		if c.execCmdReturnValue != nil {
			// Don't print out in this case, so ensure we clear it
			termInfo.Reason = ""
		} else {
			if c.connectionsLeft.Load() == 0 {
				termInfo.Reason = "No connections left in session"
			}
		}
	}

	if termInfo.Reason != "" {
		switch base.Format(c.UI) {
		case "table":
			c.UI.Output(generateTerminationInfoTableOutput(termInfo))
		case "json":
			out, err := json.Marshal(&termInfo)
			if err != nil {
				c.UI.Error(fmt.Errorf("error marshaling termination information: %w", err).Error())
				return 1
			}
			c.UI.Output(string(out))
		}
	}

	return
}

func (c *Command) handleConnection(
	listeningConn *net.TCPConn,
	workerAddr string,
	tofuToken string,
	transport *http.Transport) error {

	defer c.connWg.Done()

	conn, resp, err := websocket.Dial(
		c.proxyCtx,
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
			return errors.New("Session is unauthorized")
		case strings.Contains(err.Error(), "connect: connection refused"):
			return fmt.Errorf("Unable to connect to worker at %s", workerAddr)
		default:
			return fmt.Errorf("Error dialing the worker: %w", err)
		}
	}

	if resp == nil {
		return errors.New("Response from worker is nil")
	}
	if resp.Header == nil {
		return errors.New("Response header is nil")
	}
	negProto := resp.Header.Get("Sec-WebSocket-Protocol")
	if negProto != globals.TcpProxyV1 {
		return fmt.Errorf("Unexpected negotiated protocol: %s", negProto)
	}

	handshake := proxy.ClientHandshake{TofuToken: tofuToken}
	if err := wspb.Write(c.proxyCtx, conn, &handshake); err != nil {
		return fmt.Errorf("error sending handshake to worker: %w", err)
	}
	var handshakeResult proxy.HandshakeResult
	if err := wspb.Read(c.proxyCtx, conn, &handshakeResult); err != nil {
		switch {
		case strings.Contains(err.Error(), "unable to authorize connection"):
			// There's no reason to think we'd be able to authorize any more
			// connections after the first has failed
			c.connsLeftCh <- 0
			return errors.New("Unable to authorize connection")
		}
		return fmt.Errorf("error reading handshake result: %w", err)
	}

	if handshakeResult.GetConnectionsLeft() != -1 {
		c.connsLeftCh <- handshakeResult.GetConnectionsLeft()
	}

	// Get a wrapped net.Conn so we can use io.Copy
	netConn := websocket.NetConn(c.proxyCtx, conn, websocket.MessageBinary)

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
				c.UI.Error(fmt.Errorf("error marshaling connection information: %w", err).Error())
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
		switch c.flagHttpStyle {
		case "curl":
			if c.flagHttpMethod != "" {
				args = append(args, "-X", c.flagHttpMethod)
			}
			var uri string
			if c.flagHttpHost != "" {
				c.flagHttpHost = strings.TrimSuffix(c.flagHttpHost, "/")
				args = append(args, "-H", fmt.Sprintf("Host: %s", c.flagHttpHost))
				args = append(args, "--resolve", fmt.Sprintf("%s:%s:%s", c.flagHttpHost, port, ip))
				uri = fmt.Sprintf("%s://%s:%s", c.flagHttpScheme, c.flagHttpHost, port)
			} else {
				uri = fmt.Sprintf("%s://%s", c.flagHttpScheme, addr)
			}
			if c.flagHttpPath != "" {
				uri = fmt.Sprintf("%s/%s", uri, strings.TrimPrefix(c.flagHttpPath, "/"))
			}
			args = append(args, uri)
		}

	case "ssh":
		switch c.flagSshStyle {
		case "ssh":
			args = append(args, "-p", port, ip)
			args = append(args, "-o", fmt.Sprintf("HostKeyAlias=%s", c.sessionAuthz.HostId))
		case "putty":
			args = append(args, "-P", port, ip)
		}
		if c.flagUsername != "" {
			args = append(args, "-l", c.flagUsername)
		}

	case "postgres":
		switch c.flagPostgresStyle {
		case "psql":
			args = append(args, "-p", port, "-h", ip)
			if c.flagUsername != "" {
				args = append(args, "-U", c.flagUsername)
			}
		}

	case "rdp":
		switch c.flagRdpStyle {
		case "mstsc.exe":
			args = append(args, "/v", addr)
		case "open":
			args = append(args, "-n", "-W", fmt.Sprintf("rdp://full%saddress=s:%s", "%20", addr))
		}
	}

	args = append(passthroughArgs, args...)

	// Might want -t for ssh or -tt but seems fine without it for now...

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

		c.UI.Error(fmt.Sprintf("Failed to run command: %s", err))
		c.execCmdReturnValue.Store(int32(exitCode))
		return
	}
	c.execCmdReturnValue.Store(0)
}
