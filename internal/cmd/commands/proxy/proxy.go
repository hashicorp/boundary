package proxy

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
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
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/cmd/base"
	wpbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/boundary/internal/proxy"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/vault/sdk/helper/base62"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wspb"
)

var _ cli.Command = (*Command)(nil)
var _ cli.CommandAutocomplete = (*Command)(nil)

type Command struct {
	*base.Command

	flagAuth       string
	flagListenAddr string
	flagListenPort int
	flagVerbose    bool
}

func (c *Command) Synopsis() string {
	return "Launch the Boundary CLI in proxy mode"
}

func (c *Command) Help() string {
	return base.WrapForHelpText([]string{
		"Usage: boundary proxy [options] [args]",
		"",
		"  This command allows launching the Boundary CLI in proxy mode. In this mode, the CLI expects to take in an authorization string returned from a Boundary controller. The CLI will then create a connection to a Boundary worker and ready a listening port for a local connection.",
		"",
		"  Example:",
		"",
		`      $ boundary proxy -auth "UgxzX29mVEpwNUt6QlGiAQ..."`,
		"",
		"  Please see the {{type}}s subcommand help for detailed usage information.",
	}) + c.Flags().Help()
}

func (c *Command) Flags() *base.FlagSets {
	set := c.FlagSet(0)

	f := set.NewFlagSet("Proxy Options")

	f.StringVar(&base.StringVar{
		Name:       "auth",
		Target:     &c.flagAuth,
		EnvVar:     "BOUNDARY_PROXY_AUTH",
		Completion: complete.PredictAnything,
		Usage:      `The authorization string returned from the Boundary controller. If set to "-", the command will attempt to read in the authorization string from standard input.`,
	})

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

	var handshake proxy.Handshake
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

	if c.flagAuth == "-" {
		authBytes, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			c.UI.Error(fmt.Errorf("No authorization string was provided and encountered the following error attempting to read it from stdin: %w", err).Error())
			return 1
		}
		if len(authBytes) == 0 {
			c.UI.Error("No authorization data read from stdin")
			return 1
		}
		c.flagAuth = string(authBytes)
	}

	marshaled := base58.Decode(c.flagAuth)
	if len(marshaled) == 0 {
		c.UI.Error("Zero length authorization information after decoding")
		return 1
	}

	sessionResponseInfo := new(wpbs.GetSessionResponse)
	if err := proto.Unmarshal(marshaled, sessionResponseInfo); err != nil {
		c.UI.Error(fmt.Errorf("Unable to proto-decode authorization string: %w", err).Error())
		return 1
	}
	sessionInfo := sessionResponseInfo.GetSession()

	if len(sessionInfo.GetWorkerInfo()) == 0 {
		c.UI.Error("No workers found in authorization string")
		return 1
	}

	parsedCert, err := x509.ParseCertificate(sessionInfo.Certificate)
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
				Certificate: [][]byte{sessionInfo.Certificate},
				PrivateKey:  ed25519.PrivateKey(sessionInfo.PrivateKey),
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

	listener, err := net.ListenTCP("tcp", &net.TCPAddr{
		IP:   listenAddr,
		Port: c.flagListenPort,
	})
	if err != nil {
		c.UI.Error(fmt.Errorf("Error starting listening port: %w", err).Error())
		return 1
	}
	c.UI.Info(fmt.Sprintf("%s", listener.Addr().String()))

	workerAddr := sessionInfo.GetWorkerInfo()[0].GetAddress()

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
		c.UI.Error(fmt.Errorf("error sending tofu token to worker: %w", err).Error())
		return 1
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
