package worker

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"math/big"
	mathrand "math/rand"
	"net"
	"strings"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/cmd/base"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/go-secure-stdlib/base62"
	"google.golang.org/grpc"
	"google.golang.org/grpc/resolver"
	"google.golang.org/protobuf/proto"
)

func (w *Worker) startControllerConnections() error {
	const op = "worker.(Worker).startControllerConnections"
	initialAddrs := make([]resolver.Address, 0, len(w.conf.RawConfig.Worker.Controllers))
	for _, addr := range w.conf.RawConfig.Worker.Controllers {
		switch {
		case strings.HasPrefix(addr, "/"):
			initialAddrs = append(initialAddrs, resolver.Address{Addr: addr})
		default:
			host, port, err := net.SplitHostPort(addr)
			if err != nil && strings.Contains(err.Error(), "missing port in address") {
				host, port, err = net.SplitHostPort(net.JoinHostPort(addr, "9201"))
			}
			if err != nil {
				return fmt.Errorf("error parsing controller address: %w", err)
			}
			initialAddrs = append(initialAddrs, resolver.Address{Addr: net.JoinHostPort(host, port)})
		}
	}

	if len(initialAddrs) == 0 {
		return errors.New("no initial controller addresses found")
	}

	w.Resolver().InitialState(resolver.State{
		Addresses: initialAddrs,
	})
	if err := w.createClientConn(initialAddrs[0].Addr); err != nil {
		return fmt.Errorf("error making client connection to controller: %w", err)
	}

	return nil
}

func (w *Worker) controllerDialerFunc() func(context.Context, string) (net.Conn, error) {
	const op = "worker.(Worker).controllerDialerFunc"
	return func(ctx context.Context, addr string) (net.Conn, error) {
		tlsConf, authInfo, err := w.workerAuthTLSConfig()
		if err != nil {
			return nil, fmt.Errorf("error creating tls config for worker auth: %w", err)
		}
		dialer := &net.Dialer{}
		var nonTlsConn net.Conn
		switch {
		case strings.HasPrefix(addr, "/"):
			nonTlsConn, err = dialer.DialContext(ctx, "unix", addr)
		default:
			nonTlsConn, err = dialer.DialContext(ctx, "tcp", addr)
		}
		if err != nil {
			return nil, fmt.Errorf("unable to dial to controller: %w", err)
		}
		tlsConn := tls.Client(nonTlsConn, tlsConf)
		written, err := tlsConn.Write([]byte(authInfo.ConnectionNonce))
		if err != nil {
			if err := nonTlsConn.Close(); err != nil {
				event.WriteError(ctx, op, err, event.WithInfoMsg("error closing connection after writing failure"))
			}
			return nil, fmt.Errorf("unable to write connection nonce: %w", err)
		}
		if written != len(authInfo.ConnectionNonce) {
			if err := nonTlsConn.Close(); err != nil {
				event.WriteError(ctx, op, err, event.WithInfoMsg("error closing connection after writing failure"))
			}
			return nil, fmt.Errorf("expected to write %d bytes of connection nonce, wrote %d", len(authInfo.ConnectionNonce), written)
		}
		return tlsConn, nil
	}
}

func (w *Worker) createClientConn(addr string) error {
	const op = "worker.(Worker).createClientConn"
	defaultTimeout := (time.Second + time.Nanosecond).String()
	defServiceConfig := fmt.Sprintf(`
	  {
		"loadBalancingConfig": [ { "round_robin": {} } ],
		"methodConfig": [
		  {
			"name": [],
			"timeout": %q,
			"waitForReady": true
		  }
		]
	  }
	  `, defaultTimeout)
	res := w.Resolver()
	cc, err := grpc.DialContext(w.baseContext,
		fmt.Sprintf("%s:///%s", res.Scheme(), addr),
		grpc.WithResolvers(res),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(math.MaxInt32)),
		grpc.WithDefaultCallOptions(grpc.MaxCallSendMsgSize(math.MaxInt32)),
		grpc.WithContextDialer(w.controllerDialerFunc()),
		grpc.WithInsecure(),
		grpc.WithDefaultServiceConfig(defServiceConfig),
		// Don't have the resolver reach out for a service config from the
		// resolver, use the one specified as default
		grpc.WithDisableServiceConfig(),
	)
	if err != nil {
		return fmt.Errorf("error dialing controller for worker auth: %w", err)
	}

	w.controllerStatusConn.Store(pbs.NewServerCoordinationServiceClient(cc))
	w.controllerSessionConn.Store(pbs.NewSessionServiceClient(cc))

	event.WriteSysEvent(w.baseContext, op, "connected to controller", "address", addr)
	return nil
}

func (w *Worker) workerAuthTLSConfig() (*tls.Config, *base.WorkerAuthInfo, error) {
	var err error
	info := &base.WorkerAuthInfo{
		Name:        w.conf.RawConfig.Worker.Name,
		Description: w.conf.RawConfig.Worker.Description,
	}

	info.ConnectionNonce, err = w.nonceFn(20)
	if err != nil {
		return nil, nil, err
	}

	pubKey, privKey, err := ed25519.GenerateKey(w.conf.SecureRandomReader)
	if err != nil {
		return nil, nil, err
	}
	host, err := base62.Random(20)
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		DNSNames:              []string{host},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement | x509.KeyUsageCertSign,
		SerialNumber:          big.NewInt(mathrand.Int63()),
		NotBefore:             time.Now().Add(-30 * time.Second),
		NotAfter:              time.Now().Add(globals.WorkerAuthNonceValidityPeriod),
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certBytes, err := x509.CreateCertificate(w.conf.SecureRandomReader, template, template, pubKey, privKey)
	if err != nil {
		return nil, nil, err
	}

	certPEMBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}
	info.CertPEM = pem.EncodeToMemory(certPEMBlock)

	marshaledKey, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, nil, err
	}
	keyPEMBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: marshaledKey,
	}
	info.KeyPEM = pem.EncodeToMemory(keyPEMBlock)

	// Marshal and encrypt
	marshaledInfo, err := json.Marshal(info)
	if err != nil {
		return nil, nil, err
	}
	encInfo, err := w.conf.WorkerAuthKms.Encrypt(w.baseContext, marshaledInfo)
	if err != nil {
		return nil, nil, err
	}
	marshaledEncInfo, err := proto.Marshal(encInfo)
	if err != nil {
		return nil, nil, err
	}
	b64alpn := base64.RawStdEncoding.EncodeToString(marshaledEncInfo)
	var nextProtos []string
	var count int
	for i := 0; i < len(b64alpn); i += 230 {
		end := i + 230
		if end > len(b64alpn) {
			end = len(b64alpn)
		}
		nextProtos = append(nextProtos, fmt.Sprintf("v1workerauth-%02d-%s", count, b64alpn[i:end]))
		count++
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, err
	}

	// Build local tls config
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(cert)
	tlsCert, err := tls.X509KeyPair(info.CertPEM, info.KeyPEM)
	if err != nil {
		return nil, nil, err
	}
	tlsConfig := &tls.Config{
		ServerName:   host,
		Certificates: []tls.Certificate{tlsCert},
		RootCAs:      rootCAs,
		NextProtos:   nextProtos,
		MinVersion:   tls.VersionTLS13,
	}

	return tlsConfig, info, nil
}
