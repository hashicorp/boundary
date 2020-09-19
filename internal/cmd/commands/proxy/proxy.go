package proxy

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/btcsuite/btcutil/base58"
	"github.com/golang/protobuf/proto"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/cmd/base"
	targetspb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/targets"
	"github.com/hashicorp/boundary/internal/proxy"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/vault/sdk/helper/base62"
	"github.com/kr/pretty"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wspb"
)

type ConnectionInfo struct {
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

var _ cli.Command = (*Command)(nil)
var _ cli.CommandAutocomplete = (*Command)(nil)

type Command struct {
	*base.Command

	flagAuthz      string
	flagListenAddr string
	flagListenPort int
	flagVerbose    bool
	flagTargetId   string
	flagHostId     string

	Func string
}

func (c *Command) Synopsis() string {
	switch c.Func {
	case "proxy":
		return "Launch the Boundary CLI in proxy mode"
	case "connect":
		return "Authorize a session against a target and launch a proxied connection"
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
			`  This command performs a target authorization and proxy launch in one command; it is equivalent to sending the output of "boundary targets authorize" into "boundary proxy". See the help output for those commands for more information.`,
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

	f := set.NewFlagSet("Proxy Options")

	switch c.Func {
	case "proxy":
		f.StringVar(&base.StringVar{
			Name:       "authz",
			Target:     &c.flagAuthz,
			EnvVar:     "BOUNDARY_PROXY_AUTHZ",
			Completion: complete.PredictAnything,
			Usage:      `The authorization string returned from the Boundary controller. If set to "-", the command will attempt to read in the authorization string from standard input.`,
		})
	case "connect":
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
	}

	f.StringVar(&base.StringVar{
		Name:       "listen-addr",
		Target:     &c.flagListenAddr,
		EnvVar:     "BOUNDARY_PROXY_LISTEN_ADDR",
		Completion: complete.PredictAnything,
		Usage:      `If set, the CLI will attempt to bind its listening address to the given value, which must be an IP address. If it cannot, the command will error. If not set, defaults to the most common IPv4 loopback address (127.0.0.1)."`,
	})

	f.IntVar(&base.IntVar{
		Name:       "listen-port",
		Target:     &c.flagListenPort,
		EnvVar:     "BOUNDARY_PROXY_LISTEN_PORT",
		Completion: complete.PredictAnything,
		Usage:      `If set, the CLI will attempt to bind its listening port to the given value. If it cannot, the command will error."`,
	})

	f.BoolVar(&base.BoolVar{
		Name:       "verbose",
		Target:     &c.flagVerbose,
		Completion: complete.PredictAnything,
		Usage:      "Turns on some extra verbosity in the command output.",
	})

	return set
}

func (c *Command) AutocompleteArgs() complete.Predictor {
	return complete.PredictAnything
}

func (c *Command) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *Command) Run(args []string) int {
	f := c.Flags()

	if err := f.Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	var handshake proxy.ClientHandshake
	var err error
	if handshake.TofuToken, err = base62.Random(20); err != nil {
		c.UI.Error(fmt.Errorf("Could not derive random bytes for tofu token: %w", err).Error())
		return 1
	}

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
			// Attempt to decode the JSON output of an authorize call and pull the
			// token out of there
			var sa targets.SessionAuthorization
			if err := json.Unmarshal([]byte(authzString), &sa); err == nil {
				authzString = sa.AuthorizationToken
			}
		}

	case "connect":
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

		sar, apiErr, err := targetClient.Authorize(c.Context, c.flagTargetId, opts...)
		if err != nil {
			c.UI.Error(fmt.Sprintf("Error trying to authorize a session against target: %s", err.Error()))
			return 2
		}
		if apiErr != nil {
			c.UI.Error(fmt.Sprintf("Error from controller when performing authorize on a session against target: %s", pretty.Sprint(apiErr)))
			return 1
		}
		sa := sar.GetItem().(*targets.SessionAuthorization)
		authzString = sa.AuthorizationToken
	}

	marshaled := base58.Decode(authzString)
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

	parsedCert, err := x509.ParseCertificate(data.Certificate)
	if err != nil {
		c.UI.Error(fmt.Errorf("Unable to decode mTLS certificate: %w", err).Error())
		return 1
	}

	if len(parsedCert.DNSNames) != 1 {
		c.UI.Error(fmt.Errorf("mTLS certificate has invalid parameters: %w", err).Error())
		return 1
	}

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
	// We'll rely on the server to use the configured idle conn timeout
	transport.IdleConnTimeout = 0

	listener, err := net.ListenTCP("tcp", &net.TCPAddr{
		IP:   listenAddr,
		Port: c.flagListenPort,
	})
	if err != nil {
		c.UI.Error(fmt.Errorf("Error starting listening port: %w", err).Error())
		return 1
	}

	workerAddr := data.GetWorkerInfo()[0].GetAddress()

	conn, resp, err := websocket.Dial(
		c.Context,
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
			c.UI.Error("Session is unauthorized")
		case strings.Contains(err.Error(), "connect: connection refused"):
			c.UI.Error(fmt.Sprintf("Unable to connect to worker at %s", workerAddr))
		default:
			c.UI.Error(fmt.Errorf("Error dialing the worker: %w", err).Error())
		}
		return 1
	}

	if resp == nil {
		c.UI.Error("Response from worker is nil")
		return 1
	}
	if resp.Header == nil {
		c.UI.Error("Response header is nil")
		return 1
	}
	negProto := resp.Header.Get("Sec-WebSocket-Protocol")
	if negProto != globals.TcpProxyV1 {
		c.UI.Error(fmt.Sprintf("Unexpected negotiated protocol: %s", negProto))
		return 1
	}

	if err := wspb.Write(c.Context, conn, &handshake); err != nil {
		c.UI.Error(fmt.Errorf("error sending handshake to worker: %w", err).Error())
		return 1
	}
	var handshakeResult proxy.HandshakeResult
	if err := wspb.Read(c.Context, conn, &handshakeResult); err != nil {
		c.UI.Error(fmt.Errorf("error reading handshake result: %w", err).Error())
		return 1
	}

	listenerAddr := listener.Addr().(*net.TCPAddr)
	connInfo := ConnectionInfo{
		Protocol: "tcp",
		Address:  listenerAddr.IP.String(),
		Port:     listenerAddr.Port,
	}

	switch base.Format(c.UI) {
	case "table":
		c.UI.Output(generateConnectionInfoTableOutput(connInfo))
	case "json":
		out, err := json.Marshal(&connInfo)
		if err != nil {
			c.UI.Error(fmt.Errorf("error marshaling connection information: %w", err).Error())
			return 1
		}
		c.UI.Output(string(out))
	}

	// Get a wrapped net.Conn so we can use io.Copy
	netConn := websocket.NetConn(c.Context, conn, websocket.MessageBinary)

	// Allow closing the listener from Ctrl-C
	go func() {
		<-c.Context.Done()
		listener.Close()
	}()

	listeningConn, err := listener.AcceptTCP()
	listener.Close()
	if err != nil {
		select {
		case <-c.Context.Done():
			return 0
		default:
			c.UI.Error(fmt.Errorf("Error accepting connection: %w", err).Error())
			return 1
		}
	}

	connWg := new(sync.WaitGroup)
	connWg.Add(2)
	go func() {
		defer connWg.Done()
		_, err := io.Copy(netConn, listeningConn)
		if c.flagVerbose {
			c.UI.Info(fmt.Sprintf("copy from client to endpoint done, error: %v", err))
		}
		netConn.Close()
		listeningConn.Close()
	}()
	go func() {
		defer connWg.Done()
		_, err := io.Copy(listeningConn, netConn)
		if c.flagVerbose {
			c.UI.Info(fmt.Sprintf("copy from endpoint to client done, error: %v", err))
		}
		listeningConn.Close()
		netConn.Close()
	}()
	connWg.Wait()
	return 0
}
