package worker

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	mathrand "math/rand"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/hashicorp/vault/sdk/helper/base62"
)

type workerTLSOpts struct {
	Address string
	Protos  []string
	DumpDir string
}

type certInfo struct {
	CACert []byte `json:"ca_cert"`
	CAKey  []byte `json:"ca_key"`
}

func (c Worker) workerTLS(opts workerTLSOpts) (*tls.Config, *certInfo, error) {
	info := new(certInfo)

	certIPs := []net.IP{
		net.IPv6loopback,
		net.ParseIP("127.0.0.1"),
	}

	if opts.Address != "" {
		baseAddr, err := net.ResolveTCPAddr("tcp", opts.Address)
		if err != nil {
			return nil, nil, err
		}
		certIPs = append(certIPs, baseAddr.IP)
	}

	_, caKey, err := ed25519.GenerateKey(c.conf.SecureRandomReader)
	if err != nil {
		return nil, nil, err
	}
	info.CAKey = caKey
	caHost, err := base62.Random(20)
	if err != nil {
		return nil, nil, err
	}

	caCertTemplate := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: caHost,
		},
		DNSNames:              []string{caHost},
		IPAddresses:           certIPs,
		KeyUsage:              x509.KeyUsage(x509.KeyUsageCertSign | x509.KeyUsageCRLSign),
		SerialNumber:          big.NewInt(mathrand.Int63()),
		NotBefore:             time.Now().Add(-30 * time.Second),
		NotAfter:              time.Now().Add(262980 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caBytes, err := x509.CreateCertificate(c.conf.SecureRandomReader, caCertTemplate, caCertTemplate, caKey.Public(), caKey)
	if err != nil {
		return nil, nil, err
	}
	info.CACert = caBytes
	caCert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		return nil, nil, err
	}

	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(caCert)
	caCertPEMBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	}
	caCertPEM := pem.EncodeToMemory(caCertPEMBlock)
	caCertPEMFile := filepath.Join(opts.DumpDir, "ca_cert.pem")

	marshaledCAKey, err := x509.MarshalPKCS8PrivateKey(caKey)
	if err != nil {
		return nil, nil, err
	}
	caKeyPEMBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: marshaledCAKey,
	}
	caKeyPEM := pem.EncodeToMemory(caKeyPEMBlock)

	//
	// Certs generation
	//
	_, key, err := ed25519.GenerateKey(c.conf.SecureRandomReader)
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
		DNSNames:    []string{host},
		IPAddresses: certIPs,
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
		return nil, nil, err
	}
	certPEMBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}
	certPEM := pem.EncodeToMemory(certPEMBlock)
	marshaledKey, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	keyPEMBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: marshaledKey,
	}
	keyPEM := pem.EncodeToMemory(keyPEMBlock)

	certFile := filepath.Join(opts.DumpDir, "cert.pem")
	keyFile := filepath.Join(opts.DumpDir, "key.pem")

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, err
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		RootCAs:      rootCAs,
		ClientCAs:    rootCAs,
		ClientAuth:   tls.RequestClientCert,
		NextProtos:   opts.Protos,
		MinVersion:   tls.VersionTLS13,
	}
	tlsConfig.BuildNameToCertificate()

	if opts.DumpDir != "" {
		if _, err := os.Stat(opts.DumpDir); os.IsNotExist(err) {
			if err := os.MkdirAll(opts.DumpDir, 0700); err != nil {
				return nil, nil, err
			}
		}
		if err := ioutil.WriteFile(filepath.Join(opts.DumpDir, "ca_key.pem"), caKeyPEM, 0755); err != nil {
			return nil, nil, err
		}
		if err := ioutil.WriteFile(caCertPEMFile, caCertPEM, 0755); err != nil {
			return nil, nil, err
		}
		if err := ioutil.WriteFile(certFile, certPEM, 0755); err != nil {
			return nil, nil, err
		}
		if err := ioutil.WriteFile(keyFile, keyPEM, 0755); err != nil {
			return nil, nil, err
		}
	}

	return tlsConfig, info, nil
}
