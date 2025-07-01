// Copyright (c) Jim Lambert
// SPDX-License-Identifier: MIT

package testdirectory

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/jimlambrt/gldap"
	"github.com/stretchr/testify/require"
)

// NewMemberOf creates memberOf attributes which can be assigned to user
// entries.  Supported Options: WithDefaults
func NewMemberOf(t TestingT, groupNames []string, opt ...Option) []string {
	opts := getOpts(t, opt...)
	DNs := make([]string, 0, len(groupNames))
	for _, n := range groupNames {
		DNs = append(DNs, fmt.Sprintf("%s=%s,%s", opts.withDefaults.GroupAttr, n, opts.withDefaults.GroupDN))
	}
	return DNs
}

// NewUsers creates user entries.  Options supported: WithDefaults, WithMembersOf
func NewUsers(t TestingT, userNames []string, opt ...Option) []*gldap.Entry {
	opts := getOpts(t, opt...)

	entries := make([]*gldap.Entry, 0, len(userNames))
	for _, n := range userNames {
		entryAttrs := map[string][]string{
			"name":     {n},
			"email":    {fmt.Sprintf("%s@example.com", n)},
			"password": {"password"},
		}
		if len(opts.withMembersOf) > 0 {
			entryAttrs["memberOf"] = opts.withMembersOf
		}
		if len(opts.withTokenGroupSIDs) > 0 {
			groups := make([]string, 0, len(opts.withTokenGroupSIDs))
			for _, s := range opts.withTokenGroupSIDs {
				groups = append(groups, string(s))
			}
			entryAttrs["tokenGroups"] = groups
		}
		var DN string
		switch {
		case opts.withDefaults.UPNDomain != "":
			DN = fmt.Sprintf("userPrincipalName=%s@%s,%s", n, opts.withDefaults.UPNDomain, opts.withDefaults.UserDN)
		default:
			DN = fmt.Sprintf("%s=%s,%s", opts.withDefaults.UserAttr, n, opts.withDefaults.UserDN)
		}
		entries = append(entries,
			gldap.NewEntry(
				DN,
				entryAttrs,
			),
		)
	}
	return entries
}

// NewGroup creates a group entry.  Options supported: WithDefaults
func NewGroup(t TestingT, groupName string, memberNames []string, opt ...Option) *gldap.Entry {
	opts := getOpts(t, opt...)

	members := make([]string, 0, len(memberNames))
	for _, n := range memberNames {
		var DN string
		switch {
		case opts.withDefaults.UPNDomain != "":
			DN = fmt.Sprintf("userPrincipalName=%s@%s,%s", n, opts.withDefaults.UPNDomain, opts.withDefaults.UserDN)
		default:
			DN = fmt.Sprintf("%s=%s,%s", opts.withDefaults.UserAttr, n, opts.withDefaults.UserDN)
		}
		members = append(members, DN)
	}
	return gldap.NewEntry(
		fmt.Sprintf("%s=%s,%s", opts.withDefaults.GroupAttr, groupName, opts.withDefaults.GroupDN),
		map[string][]string{
			"member": members,
		})
}

// FreePort just returns an available free localhost port
func FreePort(t TestingT) int {
	if v, ok := interface{}(t).(HelperT); ok {
		v.Helper()
	}
	require := require.New(t)
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	require.NoError(err)

	l, err := net.ListenTCP("tcp", addr)
	require.NoError(err)
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// supports WithMTLS
func GetTLSConfig(t TestingT, opt ...Option) (s *tls.Config, c *tls.Config) {
	if v, ok := interface{}(t).(HelperT); ok {
		v.Helper()
	}
	require := require.New(t)

	certSubject := pkix.Name{
		Organization:  []string{"Acme, INC."},
		Country:       []string{"US"},
		Province:      []string{""},
		Locality:      []string{"New York"},
		StreetAddress: []string{"Empire State Building"},
		PostalCode:    []string{"10118"},
	}
	// set up our CA certificate
	ca := &x509.Certificate{
		SerialNumber:          genSerialNumber(t),
		Subject:               certSubject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caPriv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(err)

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPriv.PublicKey, caPriv)
	require.NoError(err)

	caPEM := new(bytes.Buffer)
	err = pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})
	require.NoError(err)

	privBytes, err := x509.MarshalPKCS8PrivateKey(caPriv)
	require.NoError(err)
	caPrivKeyPEM := new(bytes.Buffer)
	err = pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	})
	require.NoError(err)
	opts := getOpts(t, opt...)

	var ipAddrs []net.IP
	switch {
	case opts.withHost == "localhost":
		ipAddrs = append(ipAddrs, net.IPv4(127, 0, 0, 1))
	default:
		if hostIp := net.ParseIP(opts.withHost); hostIp != nil {
			ipAddrs = append(ipAddrs, hostIp)
		}
	}

	cert := &x509.Certificate{
		SerialNumber:          genSerialNumber(t),
		Subject:               certSubject,
		IPAddresses:           ipAddrs,
		DNSNames:              []string{opts.withHost},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		SubjectKeyId:          []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	serverCert := genCert(t, ca, caPriv, cert)

	certpool := x509.NewCertPool()
	certpool.AppendCertsFromPEM(caPEM.Bytes())

	serverTLSConf := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
	}

	clientTLSConf := &tls.Config{
		RootCAs: certpool,
	}

	if opts.withMTLS {
		// setup mTLS for certs from the ca
		serverTLSConf.ClientCAs = certpool
		serverTLSConf.ClientAuth = tls.RequireAndVerifyClientCert

		cert := &x509.Certificate{
			SerialNumber:          big.NewInt(2019),
			Subject:               certSubject,
			EmailAddresses:        []string{"mtls.client@example.com"},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().AddDate(1, 0, 0),
			SubjectKeyId:          []byte{1, 2, 3, 4, 6},
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			KeyUsage:              x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
		}
		clientCert := genCert(t, ca, caPriv, cert)
		clientTLSConf.Certificates = []tls.Certificate{clientCert}
	}

	return serverTLSConf, clientTLSConf
}

func genCert(t TestingT, ca *x509.Certificate, caPriv interface{}, certTemplate *x509.Certificate) tls.Certificate {
	if v, ok := interface{}(t).(HelperT); ok {
		v.Helper()
	}
	require := require.New(t)
	certPrivKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(err)

	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, ca, &certPrivKey.PublicKey, caPriv)
	require.NoError(err)

	certPEM := new(bytes.Buffer)
	err = pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	require.NoError(err)

	privBytes, err := x509.MarshalPKCS8PrivateKey(certPrivKey)
	require.NoError(err)

	certPrivKeyPEM := new(bytes.Buffer)
	err = pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	})
	require.NoError(err)

	newCert, err := tls.X509KeyPair(certPEM.Bytes(), certPrivKeyPEM.Bytes())
	require.NoError(err)
	return newCert
}

func genSerialNumber(t TestingT) *big.Int {
	if v, ok := interface{}(t).(HelperT); ok {
		v.Helper()
	}
	require := require.New(t)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	require.NoError(err)
	return serialNumber
}
