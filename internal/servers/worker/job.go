package worker

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
)

const (
	validateSessionTimeout = 90 * time.Second
)

func (w *Worker) getJobTls(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	var jobId string
	switch {
	case strings.HasPrefix(hello.ServerName, "s_"):
		jobId = hello.ServerName
	default:
		return nil, fmt.Errorf("could not find job ID in SNI")
	}

	rawConn := w.controllerConn.Load()
	if rawConn == nil {
		return nil, errors.New("could not get a controller client")
	}
	conn, ok := rawConn.(pbs.SessionServiceClient)
	if !ok {
		return nil, errors.New("could not cast atomic controller client to the real thing")
	}
	if conn == nil {
		return nil, errors.New("controller client is nil")
	}

	timeoutContext, cancel := context.WithTimeout(w.baseContext, validateSessionTimeout)
	defer cancel()

	resp, err := conn.GetSession(timeoutContext, &pbs.GetSessionRequest{
		Id: jobId,
	})
	if err != nil {
		return nil, fmt.Errorf("error validating session: %w", err)
	}

	parsedCert, err := x509.ParseCertificate(resp.GetSession().GetCertificate())
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
				Certificate: [][]byte{resp.GetSession().GetCertificate()},
				PrivateKey:  ed25519.PrivateKey(resp.GetSession().GetPrivateKey()),
				Leaf:        parsedCert,
			},
		},
		ServerName: parsedCert.DNSNames[0],
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  certPool,
		MinVersion: tls.VersionTLS13,
	}

	// TODO: Periodicially clean this up. We can't rely on things in here but
	// not in cancellation because they could be on the way to being
	// established. However, since cert lifetimes are short, we can simply range
	// through and remove values that are expired.
	w.jobInfoMap.Store(jobId, resp)

	return tlsConf, nil
}
