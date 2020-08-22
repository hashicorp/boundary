package worker

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/boundary/internal/gen/controller/api/services"
)

const (
	validateSessionTimeout = 90 * time.Second
)

func (w *Worker) getJobTls(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	var jobId string
	switch len(hello.SupportedProtos) {
	case 0:
		return nil, fmt.Errorf("no alpn nextproto value could be found")
	case 1:
		if hello.SupportedProtos[0] == "h2" {
			// In the future we'll handle it when we support custom certs,
			// but for now we don't support this.
			return nil, errors.New("h2 is not currently a supported alpn nextproto value")
		} else {
			jobId = hello.SupportedProtos[0]
		}
	default:
		return nil, fmt.Errorf("too many alpn nextproto values: %v", hello.SupportedProtos)
	}

	rawConn := w.controllerConn.Load()
	if rawConn == nil {
		return nil, errors.New("could not get a controller client")
	}
	conn, ok := rawConn.(services.WorkerServiceClient)
	if !ok {
		return nil, errors.New("could not cast atomic controller client to the real thing")
	}
	if conn == nil {
		return nil, errors.New("controller client is nil")
	}

	timeoutContext, cancel := context.WithTimeout(w.baseContext, validateSessionTimeout)
	defer cancel()

	resp, err := conn.ValidateSession(timeoutContext, &services.ValidateSessionRequest{
		Id: jobId,
	})
	if err != nil {
		return nil, fmt.Errorf("error validating session: %w", err)
	}

	parsedCert, err := x509.ParseCertificate(resp.GetCertificate())
	if err != nil {
		return nil, fmt.Errorf("error parsing session certificate: %w", err)
	}

	if len(parsedCert.DNSNames) != 1 {
		return nil, fmt.Errorf("invalid length of DNS names (%d) in parsed certificate", len(parsedCert.DNSNames))
	}

	certPool := x509.NewCertPool()
	certPool.AddCert(parsedCert)

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{resp.GetCertificate()},
				PrivateKey:  ed25519.PrivateKey(resp.GetPrivateKey()),
				Leaf:        parsedCert,
			},
		},
		NextProtos: []string{parsedCert.DNSNames[0]},
		ServerName: parsedCert.DNSNames[0],
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  certPool,
		MinVersion: tls.VersionTLS13,
	}

	//log.Println(litter.Sdump(tlsConf))

	return tlsConf, nil
}
