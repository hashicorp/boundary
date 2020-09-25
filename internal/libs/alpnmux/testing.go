package alpnmux

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	mathrand "math/rand"
	"net"
	"testing"
	"time"
)

func getListener(t *testing.T) net.Listener {
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.ListenTCP("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	return listener
}

func getTestTLS(t *testing.T, protos []string) *tls.Config {
	certIPs := []net.IP{
		net.IPv6loopback,
		net.ParseIP("127.0.0.1"),
	}

	_, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caCertTemplate := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		DNSNames:              []string{"localhost"},
		IPAddresses:           certIPs,
		KeyUsage:              x509.KeyUsage(x509.KeyUsageCertSign | x509.KeyUsageCRLSign),
		SerialNumber:          big.NewInt(mathrand.Int63()),
		NotBefore:             time.Now().Add(-30 * time.Second),
		NotAfter:              time.Now().Add(262980 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, caCertTemplate, caCertTemplate, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		t.Fatal(err)
	}
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(caCert)

	//
	// Certs generation
	//
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certTemplate := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		DNSNames:    []string{"localhost"},
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
	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, caCert, key.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEMBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}
	certPEM := pem.EncodeToMemory(certPEMBlock)
	marshaledKey, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEMBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: marshaledKey,
	}
	keyPEM := pem.EncodeToMemory(keyPEMBlock)

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		RootCAs:      rootCAs,
		ClientCAs:    rootCAs,
		ClientAuth:   tls.RequestClientCert,
		NextProtos:   protos,
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
	}

	return tlsConfig
}
