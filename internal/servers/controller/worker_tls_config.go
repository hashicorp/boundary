package controller

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"strings"

	"github.com/hashicorp/boundary/internal/cmd/base"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"google.golang.org/protobuf/proto"
)

type workerAuthEntry struct {
	*base.WorkerAuthInfo
	conn net.Conn
}

func (c Controller) validateWorkerTls(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	for _, p := range hello.SupportedProtos {
		switch {
		case strings.HasPrefix(p, "v1workerauth-"):
			tlsConf, workerInfo, err := c.v1WorkerAuthConfig(hello.SupportedProtos)
			if err == nil {
				// Set the info we need to prevent replays
				c.workerAuthCache.Set(workerInfo.ConnectionNonce, &workerAuthEntry{
					WorkerAuthInfo: workerInfo,
				}, 0)
			}
			return tlsConf, err
		}
	}
	return nil, nil
}

func (c Controller) v1WorkerAuthConfig(protos []string) (*tls.Config, *base.WorkerAuthInfo, error) {
	var firstMatchProto string
	var encString string
	for _, p := range protos {
		if strings.HasPrefix(p, "v1workerauth-") {
			// Strip that and the number
			encString += strings.TrimPrefix(p, "v1workerauth-")[3:]
			if firstMatchProto == "" {
				firstMatchProto = p
			}
		}
	}
	if firstMatchProto == "" {
		return nil, nil, errors.New("no matching proto found")
	}
	marshaledEncInfo, err := base64.RawStdEncoding.DecodeString(encString)
	if err != nil {
		return nil, nil, err
	}
	encInfo := new(wrapping.BlobInfo)
	if err := proto.Unmarshal(marshaledEncInfo, encInfo); err != nil {
		return nil, nil, err
	}
	marshaledInfo, err := c.conf.WorkerAuthKms.Decrypt(context.Background(), encInfo)
	if err != nil {
		return nil, nil, err
	}
	info := new(base.WorkerAuthInfo)
	if err := json.Unmarshal(marshaledInfo, info); err != nil {
		return nil, nil, err
	}

	rootCAs := x509.NewCertPool()
	if ok := rootCAs.AppendCertsFromPEM(info.CertPEM); !ok {
		return nil, info, errors.New("unable to add ca cert to cert pool")
	}
	tlsCert, err := tls.X509KeyPair(info.CertPEM, info.KeyPEM)
	if err != nil {
		return nil, info, err
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		ClientCAs:    rootCAs,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		NextProtos:   []string{firstMatchProto},
		MinVersion:   tls.VersionTLS13,
	}

	return tlsConfig, info, nil
}
