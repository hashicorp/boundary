package targets

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/globals"
	targetspb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/targets"
	"github.com/hashicorp/boundary/internal/proxy"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/mr-tron/base58"
	"google.golang.org/protobuf/proto"
	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wspb"
)

type SessionAuthorizationResult struct {
	Item     *SessionAuthorization
	response *api.Response
}

func (n SessionAuthorizationResult) GetItem() interface{} {
	return n.Item
}

func (n SessionAuthorizationResult) GetResponse() *api.Response {
	return n.response
}

type SessionAuthorizationData struct {
	SessionId       string
	TargetId        string
	Type            string
	ConnectionLimit int32
	Certificate     []byte
	PrivateKey      []byte
	HostId          string
	Endpoint        string
	WorkerInfo      []*WorkerInfo
}

func (x *SessionAuthorizationData) GetEndpoint() string {
	if x != nil {
		return x.Endpoint
	}
	return ""
}

func (x *SessionAuthorizationData) GetConnectionLimit() int32 {
	if x != nil {
		return x.ConnectionLimit
	}
	return 0
}

func (x *SessionAuthorizationData) GetSessionId() string {
	if x != nil {
		return x.SessionId
	}
	return ""
}

type AuthorizationToken string

func (t AuthorizationToken) Connect(ctx context.Context, transport *http.Transport) (*websocket.Conn, error) {
	sessionAuthzData, tlsConf, err := t.GetConfig()
	if err != nil {
		return nil, err
	}
	workerAddr := sessionAuthzData.WorkerInfo[0].Address

	if transport == nil {
		transport = cleanhttp.DefaultTransport()
		transport.DisableKeepAlives = false
		transport.TLSClientConfig = tlsConf
		// This isn't/shouldn't used anyways really because the connection is
		// hijacked, just setting for completeness
		transport.IdleConnTimeout = 0
	}

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

func (t AuthorizationToken) GetConfig() (*SessionAuthorizationData, *tls.Config, error) {
	marshaled, err := base58.FastBase58Decoding(string(t))
	if err != nil {
		return nil, nil, fmt.Errorf("Unable to base58-decode authorization data: %w", err)
	}
	if len(marshaled) == 0 {
		return nil, nil, errors.New("Zero length authorization information after decoding")
	}
	sessionAuthzData := new(targetspb.SessionAuthorizationData)

	if err := proto.Unmarshal(marshaled, sessionAuthzData); err != nil {
		return nil, nil, fmt.Errorf("Unable to proto-decode authorization data: %w", err)
	}

	if len(sessionAuthzData.GetWorkerInfo()) == 0 {
		return nil, nil, errors.New("No workers found in authorizationo string")
	}

	parsedCert, err := x509.ParseCertificate(sessionAuthzData.Certificate)
	if err != nil {
		return nil, nil, fmt.Errorf("Unable to decode mTLS certificate: %w", err)
	}

	if len(parsedCert.DNSNames) != 1 {
		return nil, nil, fmt.Errorf("mTLS certificate has invalid parameters: %w", err)
	}

	certPool := x509.NewCertPool()
	certPool.AddCert(parsedCert)

	data := &SessionAuthorizationData{
		SessionId:       sessionAuthzData.SessionId,
		TargetId:        sessionAuthzData.TargetId,
		Type:            sessionAuthzData.Type,
		ConnectionLimit: sessionAuthzData.ConnectionLimit,
		Certificate:     sessionAuthzData.Certificate,
		PrivateKey:      sessionAuthzData.PrivateKey,
		HostId:          sessionAuthzData.HostId,
		Endpoint:        sessionAuthzData.Endpoint,
	}

	for _, worker := range sessionAuthzData.WorkerInfo {
		data.WorkerInfo = append(data.WorkerInfo, &WorkerInfo{
			Address: worker.Address,
		})
	}

	return data, &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{sessionAuthzData.Certificate},
				PrivateKey:  ed25519.PrivateKey(sessionAuthzData.PrivateKey),
				Leaf:        parsedCert,
			},
		},
		RootCAs:    certPool,
		ServerName: parsedCert.DNSNames[0],
		MinVersion: tls.VersionTLS13,
	}, nil
}

func (c *Client) AuthorizeSession(ctx context.Context, targetId string, opt ...Option) (*SessionAuthorizationResult, error) {
	opts, apiOpts := getOpts(opt...)

	if targetId == "" {
		if opts.postMap["name"] == nil {
			return nil, fmt.Errorf("empty target name provided to AuthorizeSession request")
		}
		scopeIdEmpty := opts.postMap["scope_id"] == nil
		scopeNameEmpty := opts.postMap["scope_name"] == nil
		switch {
		case scopeIdEmpty && scopeNameEmpty:
			return nil, fmt.Errorf("empty targetId value and no combination of target name and scope ID/name passed into AuthorizeSession request")
		case !scopeIdEmpty && !scopeNameEmpty:
			return nil, fmt.Errorf("both scope ID and scope name cannot be provided in AuthorizeSession request")
		default:
			// Name is not empty and only one of scope ID or name set
			targetId = opts.postMap["name"].(string)
		}
	}

	if c.client == nil {
		return nil, fmt.Errorf("nil client")
	}

	req, err := c.client.NewRequest(ctx, "POST", fmt.Sprintf("targets/%s:authorize-session", targetId), opts.postMap, apiOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating AuthorizeSession request: %w", err)
	}

	if len(opts.queryMap) > 0 {
		q := url.Values{}
		for k, v := range opts.queryMap {
			q.Add(k, v)
		}
		req.URL.RawQuery = q.Encode()
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error performing client request during AuthorizeSession call: %w", err)
	}

	target := new(SessionAuthorizationResult)
	target.Item = new(SessionAuthorization)
	apiErr, err := resp.Decode(target.Item)
	if err != nil {
		return nil, fmt.Errorf("error decoding AuthorizeSession response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr
	}
	target.response = resp
	return target, nil
}

func Handshake(ctx context.Context, wsConn *websocket.Conn, tofuToken string) error {
	handshake := proxy.ClientHandshake{TofuToken: tofuToken}
	if err := wspb.Write(ctx, wsConn, &handshake); err != nil {
		return fmt.Errorf("error sending handshake to worker: %w", err)
	}
	var handshakeResult proxy.HandshakeResult
	if err := wspb.Read(ctx, wsConn, &handshakeResult); err != nil {
		switch {
		case strings.Contains(err.Error(), "unable to authorize connection"):
			return errors.New("Unable to authorize connection")
		}
		switch {
		case strings.Contains(err.Error(), "tofu token not allowed"):
			return errors.New("Session is already in use")
		default:
			return fmt.Errorf("error reading handshake result: %w", err)
		}
	}
	return nil
}
