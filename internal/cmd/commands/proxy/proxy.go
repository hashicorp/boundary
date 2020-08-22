package proxy

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/golang/protobuf/proto"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
	"nhooyr.io/websocket"
)

var _ cli.Command = (*Command)(nil)
var _ cli.CommandAutocomplete = (*Command)(nil)

const (
	supportedProto = "boundary-proxy-v1"
)

type Command struct {
	*base.Command

	flagAuth       string
	flagListenPort int
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

	f.IntVar(&base.IntVar{
		Name:       "listen-port",
		Target:     &c.flagListenPort,
		EnvVar:     "BOUNDARY_PROXY_LISTEN_PORT",
		Completion: complete.PredictAnything,
		Usage:      `If set, the CLI will attempt to bind its listening port to the given value. If it cannot, the command will error."`,
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

	marshaled, err := base64.RawStdEncoding.DecodeString(c.flagAuth)
	if err != nil {
		c.UI.Error(fmt.Errorf("Unable to decode authorization string: %w", err).Error())
		return 1
	}

	sessionInfo := new(services.ValidateSessionResponse)
	if err := proto.Unmarshal(marshaled, sessionInfo); err != nil {
		c.UI.Error(fmt.Errorf("Unable to proto-decode authorization string: %w", err).Error())
		return 1
	}

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

	conn, resp, err := websocket.Dial(
		c.Context,
		fmt.Sprintf("wss://%s/v1/proxy", sessionInfo.GetWorkerInfo()[0].GetAddress()),
		&websocket.DialOptions{
			HTTPClient: &http.Client{
				Transport: transport,
			},
			Subprotocols: []string{supportedProto},
		},
	)
	if err != nil {
		c.UI.Error(fmt.Errorf("Error dialing the worker: %w", err).Error())
		return 1
	}
	// TODO: Is this needed, or is the context sufficient?
	//defer conn.Close(websocket.StatusNormalClosure, "done-client")
	_ = conn

	if resp == nil {
		c.UI.Error("Response from worker is nil")
		return 1
	}
	if resp.Header == nil {
		c.UI.Error("Response header is nil")
		return 1
	}
	negProto := resp.Header.Get("Sec-WebSocket-Protocol")
	if negProto != supportedProto {
		c.UI.Error(fmt.Sprintf("Unexpected negotiated protocol: %s", negProto))
		return 1
	}

	return 0
}
