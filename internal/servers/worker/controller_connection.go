package worker

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math"
	"math/big"
	mathrand "math/rand"
	"net"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/helper/base62"
	"github.com/hashicorp/watchtower/internal/cmd/base"
	"github.com/hashicorp/watchtower/internal/gen/controller/api/services"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

type controllerConnection struct {
	controllerAddr string
	client         services.WorkerServiceClient
}

func newControllerConnection(controllerAddr string, client services.WorkerServiceClient) *controllerConnection {
	ret := &controllerConnection{
		controllerAddr: controllerAddr,
		client:         client,
	}

	return ret
}

func (w *Worker) startControllerConnections() error {
	for _, addr := range w.conf.RawConfig.Worker.Controllers {
		host, port, err := net.SplitHostPort(addr)
		if err != nil && strings.Contains(err.Error(), "missing port in address") {
			host, port, err = net.SplitHostPort(fmt.Sprintf("%s:%s", addr, "9201"))
		}
		if err != nil {
			return fmt.Errorf("error parsing controller address: %w", err)
		}

		if err := w.createClientConn(fmt.Sprintf("%s:%s", host, port)); err != nil {
			return fmt.Errorf("error making client connection to controller: %w", err)
		}
	}

	return nil
}

func (w Worker) controllerDialerFunc() func(context.Context, string) (net.Conn, error) {
	return func(ctx context.Context, addr string) (net.Conn, error) {
		tlsConf, authInfo, err := w.workerAuthTLSConfig()
		if err != nil {
			return nil, fmt.Errorf("error creating tls config for worker auth: %w", err)
		}
		dialer := &net.Dialer{}
		nonTlsConn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("unable to dial to controller: %w", err)
		}
		tlsConn := tls.Client(nonTlsConn, tlsConf)
		written, err := tlsConn.Write([]byte(authInfo.ConnectionNonce))
		if err != nil {
			if err := nonTlsConn.Close(); err != nil {
				w.logger.Error("error closing connection after writing failure", "error", err)
			}
			return nil, fmt.Errorf("unable to write connection nonce: %w", err)
		}
		if written != len(authInfo.ConnectionNonce) {
			if err := nonTlsConn.Close(); err != nil {
				w.logger.Error("error closing connection after writing failure", "error", err)
			}
			return nil, fmt.Errorf("expected to write %d bytes of connection nonce, wrote %d", len(authInfo.ConnectionNonce), written)
		}
		return tlsConn, nil
	}
}

func (w *Worker) createClientConn(addr string) error {
	cc, err := grpc.DialContext(w.baseContext, addr,
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(math.MaxInt32)),
		grpc.WithDefaultCallOptions(grpc.MaxCallSendMsgSize(math.MaxInt32)),
		grpc.WithContextDialer(w.controllerDialerFunc()),
		grpc.WithInsecure(),
	)
	if err != nil {
		return fmt.Errorf("error dialing controller for worker auth: %w", err)
	}

	client := services.NewWorkerServiceClient(cc)
	w.controllerConns = append(w.controllerConns, newControllerConnection(addr, client))

	w.logger.Info("connected to controller", "address", addr)
	return nil
}

func (w Worker) workerAuthTLSConfig() (*tls.Config, *base.WorkerAuthInfo, error) {
	var err error
	info := &base.WorkerAuthInfo{
		Name:        w.conf.RawConfig.Worker.Name,
		Description: w.conf.RawConfig.Worker.Description,
	}
	if info.ConnectionNonce, err = base62.Random(20); err != nil {
		return nil, nil, err
	}

	_, caKey, err := ed25519.GenerateKey(w.conf.SecureRandomReader)
	if err != nil {
		return nil, nil, err
	}
	caHost, err := base62.Random(20)
	if err != nil {
		return nil, nil, err
	}

	caCertTemplate := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: caHost,
		},
		DNSNames:              []string{caHost},
		KeyUsage:              x509.KeyUsage(x509.KeyUsageCertSign | x509.KeyUsageCRLSign),
		SerialNumber:          big.NewInt(mathrand.Int63()),
		NotBefore:             time.Now().Add(-30 * time.Second),
		NotAfter:              time.Now().Add(3 * time.Minute),
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caBytes, err := x509.CreateCertificate(w.conf.SecureRandomReader, caCertTemplate, caCertTemplate, caKey.Public(), caKey)
	if err != nil {
		return nil, nil, err
	}
	caCertPEMBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	}
	info.CACertPEM = pem.EncodeToMemory(caCertPEMBlock)
	caCert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		return nil, nil, err
	}

	//
	// Certs generation
	//
	_, key, err := ed25519.GenerateKey(w.conf.SecureRandomReader)
	if err != nil {
		return nil, nil, err
	}
	host, err := base62.Random(20)
	if err != nil {
		return nil, nil, err
	}
	certTemplate := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: host,
		},
		DNSNames: []string{host},
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement,
		SerialNumber: big.NewInt(mathrand.Int63()),
		NotBefore:    time.Now().Add(-30 * time.Second),
		NotAfter:     time.Now().Add(2 * time.Minute),
	}
	certBytes, err := x509.CreateCertificate(w.conf.SecureRandomReader, certTemplate, caCert, key.Public(), caKey)
	if err != nil {
		return nil, nil, err
	}
	certPEMBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}
	info.CertPEM = pem.EncodeToMemory(certPEMBlock)
	marshaledKey, err := x509.MarshalPKCS8PrivateKey(key)
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
	encInfo, err := w.conf.WorkerAuthKMS.Encrypt(context.Background(), marshaledInfo, nil)
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

	// Build local tls config
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(caCert)
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
	tlsConfig.BuildNameToCertificate()

	return tlsConfig, info, nil
}
