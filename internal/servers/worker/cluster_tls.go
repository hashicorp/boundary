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
	"math/big"
	mathrand "math/rand"
	"time"

	"github.com/hashicorp/vault/sdk/helper/base62"
	"github.com/hashicorp/watchtower/internal/cmd/base"
	"google.golang.org/protobuf/proto"
)

func (c Worker) workerAuthTLSConfig() (*tls.Config, error) {
	info := new(base.WorkerAuthCertInfo)

	_, caKey, err := ed25519.GenerateKey(c.conf.SecureRandomReader)
	if err != nil {
		return nil, err
	}
	caHost, err := base62.Random(20)
	if err != nil {
		return nil, err
	}

	caCertTemplate := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: caHost,
		},
		DNSNames:              []string{caHost},
		KeyUsage:              x509.KeyUsage(x509.KeyUsageCertSign | x509.KeyUsageCRLSign),
		SerialNumber:          big.NewInt(mathrand.Int63()),
		NotBefore:             time.Now().Add(-30 * time.Second),
		NotAfter:              time.Now().Add(262980 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caBytes, err := x509.CreateCertificate(c.conf.SecureRandomReader, caCertTemplate, caCertTemplate, caKey.Public(), caKey)
	if err != nil {
		return nil, err
	}
	caCertPEMBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	}
	info.CACertPEM = pem.EncodeToMemory(caCertPEMBlock)
	caCert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		return nil, err
	}

	//
	// Certs generation
	//
	_, key, err := ed25519.GenerateKey(c.conf.SecureRandomReader)
	if err != nil {
		return nil, err
	}
	host, err := base62.Random(20)
	if err != nil {
		return nil, err
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
		NotAfter:     time.Now().Add(262980 * time.Hour),
	}
	certBytes, err := x509.CreateCertificate(c.conf.SecureRandomReader, certTemplate, caCert, key.Public(), caKey)
	if err != nil {
		return nil, err
	}
	certPEMBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}
	info.CertPEM = pem.EncodeToMemory(certPEMBlock)
	marshaledKey, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEMBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: marshaledKey,
	}
	info.KeyPEM = pem.EncodeToMemory(keyPEMBlock)

	// Marshal and encrypt
	marshaledInfo, err := json.Marshal(info)
	if err != nil {
		return nil, err
	}
	encInfo, err := c.conf.WorkerAuthKMS.Encrypt(context.Background(), marshaledInfo, nil)
	if err != nil {
		return nil, err
	}
	marshaledEncInfo, err := proto.Marshal(encInfo)
	if err != nil {
		return nil, err
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
		return nil, err
	}
	tlsConfig := &tls.Config{
		ServerName:   host,
		Certificates: []tls.Certificate{tlsCert},
		RootCAs:      rootCAs,
		NextProtos:   nextProtos,
		MinVersion:   tls.VersionTLS13,
	}
	tlsConfig.BuildNameToCertificate()

	return tlsConfig, nil
}
