package vault

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-rootcerts"
	vault "github.com/hashicorp/vault/api"
	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVaultTLS represents the TLS configuration level of a
// TestVaultServer.
type TestVaultTLS int

const (
	// TestNoTLS disables TLS. The test server Addr begins with http://.
	TestNoTLS TestVaultTLS = iota // no TLS

	// TestServerTLS configures the Vault test server listener to use TLS.
	// A CA certificate is generated and a server certificate is issued
	// from the CA certificate. The CA certificate is available in the
	// CaCert field of the TestVaultServer. The test server Addr begins
	// with https://.
	TestServerTLS

	// TestClientTLS configures the Vault test server listener to require a
	// client certificate for mTLS and includes all of the settings from
	// TestServerTLS. A second CA certificate is generated and a client
	// certificate is issued from this CA certificate. The client
	// certificate and the client certificate key are available in the in
	// the ClientCert and ClientKey fields of the TestVaultServer
	// respectively.
	TestClientTLS
)

// TestVaultServer is a vault server running in a docker container suitable
// for testing.
type TestVaultServer struct {
	RootToken string
	Addr      string

	CaCert     []byte
	ClientCert []byte
	ClientKey  []byte
}

// NewTestVaultServer creates and returns a TestVaultServer and a cleanup
// function which must be called when the vault server is no longer needed.
func NewTestVaultServer(t *testing.T, testTls TestVaultTLS) (*TestVaultServer, func()) {
	t.Helper()

	switch testTls {
	case TestServerTLS, TestClientTLS:
		return newTestVaultServerTLS(t, testTls)
	default:
	}

	require := require.New(t)
	pool, err := dockertest.NewPool("")
	require.NoError(err)

	server := &TestVaultServer{
		RootToken: fmt.Sprintf("icu-root-%s", t.Name()),
	}

	env := []string{
		fmt.Sprintf("VAULT_DEV_ROOT_TOKEN_ID=%s", server.RootToken),
	}

	dockerOptions := &dockertest.RunOptions{
		Repository: "vault",
		Tag:        "1.7.0",
		Env:        env,
	}

	resource, err := pool.RunWithOptions(dockerOptions)
	require.NoError(err)
	cleanup := func() {
		cleanupResource(t, pool, resource)
	}
	server.Addr = fmt.Sprintf("http://localhost:%s", resource.GetPort("8200/tcp"))

	vConfig := vault.DefaultConfig()
	vConfig.Address = server.Addr

	client, err := vault.NewClient(vConfig)
	require.NoError(err)
	client.SetToken(server.RootToken)

	err = pool.Retry(func() error {
		if _, err := client.Sys().Health(); err != nil {
			return err
		}
		return nil
	})
	require.NoError(err)
	return server, cleanup
}

func newTestVaultServerTLS(t *testing.T, testTls TestVaultTLS) (*TestVaultServer, func()) {
	t.Helper()
	const (
		serverTlsTemplate = `{
  "listener": [
    {
      "tcp": {
        "address": "0.0.0.0:8200",
        "tls_disable": "false",
        "tls_cert_file": "/vault/config/certificates/certificate.pem",
        "tls_key_file": "/vault/config/certificates/key.pem"
      }
    }
  ]
}
`

		clientTlsTemplate = `{
  "listener": [
    {
      "tcp": {
        "address": "0.0.0.0:8200",
        "tls_disable": "false",
        "tls_cert_file": "/vault/config/certificates/certificate.pem",
        "tls_key_file": "/vault/config/certificates/key.pem",
		"tls_require_and_verify_client_cert": "true",
		"tls_client_ca_file": "/vault/config/certificates/client-ca-certificate.pem"
      }
    }
  ]
}
`
	)
	template := serverTlsTemplate

	assert, require := assert.New(t), require.New(t)
	pool, err := dockertest.NewPool("")
	require.NoError(err)

	server := &TestVaultServer{
		RootToken: fmt.Sprintf("icu-root-%s", t.Name()),
	}

	serverCert := testServerCert(t, testCaCert(t), "localhost")
	server.CaCert = serverCert.CA.Cert

	dataSrcDir, err := ioutil.TempDir("", strings.ReplaceAll(t.Name(), "/", "-"))
	require.NoError(err)
	t.Log(dataSrcDir)
	require.NoError(os.Chmod(dataSrcDir, 0o777))
	cleanupDataDir := func() {
		os.RemoveAll(dataSrcDir) // clean up
	}

	caCertFn := filepath.Join(dataSrcDir, "ca-certificate.pem")
	ioutil.WriteFile(caCertFn, serverCert.CA.Cert, 0o777)
	certFn := filepath.Join(dataSrcDir, "certificate.pem")
	ioutil.WriteFile(certFn, serverCert.Cert.Cert, 0o777)
	keyFn := filepath.Join(dataSrcDir, "key.pem")
	ioutil.WriteFile(keyFn, serverCert.Cert.Key, 0o777)

	var clientCert *testCertBundle
	if testTls == TestClientTLS {
		template = clientTlsTemplate
		clientCert = testClientCert(t, testCaCert(t))
		server.ClientCert = clientCert.Cert.Cert
		server.ClientKey = clientCert.Cert.Key
		clientCaCertFn := filepath.Join(dataSrcDir, "client-ca-certificate.pem")
		ioutil.WriteFile(clientCaCertFn, clientCert.CA.Cert, 0o777)
	}

	env := []string{
		fmt.Sprintf("VAULT_DEV_ROOT_TOKEN_ID=%s", server.RootToken),
		fmt.Sprintf("VAULT_LOCAL_CONFIG=%s", template),
		"VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8300",
	}

	dataMount := fmt.Sprintf("%s:/vault/config/certificates", dataSrcDir)
	dockerOptions := &dockertest.RunOptions{
		Repository: "vault",
		Tag:        "1.7.0",
		Mounts:     []string{dataMount},
		Env:        env,
	}

	resource, err := pool.RunWithOptions(dockerOptions)
	if !assert.NoError(err) {
		cleanupDataDir()
		t.FailNow()
	}
	cleanup := func() {
		cleanupResource(t, pool, resource)
		cleanupDataDir()
	}
	server.Addr = fmt.Sprintf("https://localhost:%s", resource.GetPort("8200/tcp"))

	vConfig := vault.DefaultConfig()
	vConfig.Address = server.Addr

	clientTLSConfig := vConfig.HttpClient.Transport.(*http.Transport).TLSClientConfig
	rootConfig := &rootcerts.Config{
		CACertificate: serverCert.CA.Cert,
	}

	if !assert.NoError(rootcerts.ConfigureTLS(clientTLSConfig, rootConfig)) {
		cleanup()
		t.FailNow()
	}

	if testTls == TestClientTLS {
		vaultClientCert, err := tls.X509KeyPair(server.ClientCert, server.ClientKey)
		if !assert.NoError(err) {
			cleanup()
			t.FailNow()
		}
		clientTLSConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &vaultClientCert, nil
		}
	}

	client, err := vault.NewClient(vConfig)
	if !assert.NoError(err) {
		cleanup()
		t.FailNow()
	}
	client.SetToken(server.RootToken)

	err = pool.Retry(func() error {
		if _, err := client.Sys().Health(); err != nil {
			return err
		}
		return nil
	})
	if !assert.NoError(err) {
		cleanup()
		t.FailNow()
	}
	return server, cleanup
}

func cleanupResource(t *testing.T, pool *dockertest.Pool, resource *dockertest.Resource) {
	t.Helper()
	var err error
	for i := 0; i < 10; i++ {
		err = pool.Purge(resource)
		if err == nil {
			return
		}
		time.Sleep(1 * time.Second)
	}

	if strings.Contains(err.Error(), "No such container") {
		return
	}
	t.Fatalf("Failed to cleanup local container: %s", err)
}

type testCert struct {
	Cert []byte
	Key  []byte

	certificate *x509.Certificate
	priv        *ecdsa.PrivateKey
}

type testCertBundle struct {
	CA   testCert
	Cert testCert
}

// testCaCert will generate a test x509 CA cert.
func testCaCert(t *testing.T) *testCert {
	t.Helper()
	require := require.New(t)

	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(err)

	// ECDSA, ED25519 and RSA subject keys should have the DigitalSignature
	// KeyUsage bits set in the x509.Certificate template
	keyUsage := x509.KeyUsageDigitalSignature

	notBefore, notAfter := time.Now(), time.Now().Add(24*time.Hour)
	if deadLine, ok := t.Deadline(); ok {
		notAfter = deadLine
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	require.NoError(err)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme CA"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              keyUsage | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(err)

	c, err := x509.ParseCertificate(derBytes)
	require.NoError(err)

	k, err := x509.MarshalECPrivateKey(priv)
	require.NoError(err)

	return &testCert{
		Cert:        pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}),
		Key:         pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: k}),
		certificate: c,
		priv:        priv,
	}
}

// testServerCert will generate a test x509 server cert.
func testServerCert(t *testing.T, ca *testCert, hosts ...string) *testCertBundle {
	t.Helper()
	require := require.New(t)

	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(err)

	// ECDSA, ED25519 and RSA subject keys should have the DigitalSignature
	// KeyUsage bits set in the x509.Certificate template
	keyUsage := x509.KeyUsageDigitalSignature

	notBefore, notAfter := time.Now(), time.Now().Add(24*time.Hour)
	if deadLine, ok := t.Deadline(); ok {
		notAfter = deadLine
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	require.NoError(err)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Servers Inc"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  false,
		BasicConstraintsValid: true,
	}

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, ca.certificate, &priv.PublicKey, ca.priv)
	require.NoError(err)

	c, err := x509.ParseCertificate(derBytes)
	require.NoError(err)

	k, err := x509.MarshalECPrivateKey(priv)
	require.NoError(err)

	serverCert := &testCert{
		Cert:        pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}),
		Key:         pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: k}),
		certificate: c,
		priv:        priv,
	}

	return &testCertBundle{
		CA:   *ca,
		Cert: *serverCert,
	}
}

// testClientCert will generate a test x509 client cert.
func testClientCert(t *testing.T, ca *testCert) *testCertBundle {
	t.Helper()
	require := require.New(t)

	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(err)

	// ECDSA, ED25519 and RSA subject keys should have the DigitalSignature
	// KeyUsage bits set in the x509.Certificate template
	keyUsage := x509.KeyUsageDigitalSignature

	notBefore, notAfter := time.Now(), time.Now().Add(24*time.Hour)
	if deadLine, ok := t.Deadline(); ok {
		notAfter = deadLine
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	require.NoError(err)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Clients Inc"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		IsCA:                  false,
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, ca.certificate, &priv.PublicKey, ca.priv)
	require.NoError(err)

	c, err := x509.ParseCertificate(derBytes)
	require.NoError(err)

	k, err := x509.MarshalECPrivateKey(priv)
	require.NoError(err)

	serverCert := &testCert{
		Cert:        pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}),
		Key:         pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: k}),
		certificate: c,
		priv:        priv,
	}

	return &testCertBundle{
		CA:   *ca,
		Cert: *serverCert,
	}
}

func getTestTokenOpts(t *testing.T, opt ...TestOption) testOptions {
	t.Helper()
	opts := getDefaultTestOptions(t)
	for _, o := range opt {
		o(t, &opts)
	}
	return opts
}

// TestOption - how Options are passed as arguments.
type TestOption func(*testing.T, *testOptions)

// options = how options are represented
type testOptions struct {
	orphan    bool
	periodic  bool
	renewable bool
	policies  []string
}

func getDefaultTestOptions(t *testing.T) testOptions {
	t.Helper()
	return testOptions{
		orphan:    true,
		periodic:  true,
		renewable: true,
		policies:  []string{"default"},
	}
}

// TestOrphanToken sets the token orphan option to b.
// The orphan option is true by default.
func TestOrphanToken(t *testing.T, b bool) TestOption {
	return func(t *testing.T, o *testOptions) {
		t.Helper()
		o.orphan = b
	}
}

// TestPeriodicToken sets the token periodic option to b.
// The periodic option is true by default.
func TestPeriodicToken(t *testing.T, b bool) TestOption {
	return func(t *testing.T, o *testOptions) {
		t.Helper()
		o.periodic = b
	}
}

// TestRenewableToken sets the token renewable option to b.
// The renewable option is true by default.
func TestRenewableToken(t *testing.T, b bool) TestOption {
	return func(t *testing.T, o *testOptions) {
		t.Helper()
		o.renewable = b
	}
}

func (v *TestVaultServer) client(t *testing.T) *client {
	t.Helper()
	require := require.New(t)
	conf := &clientConfig{
		Addr:       v.Addr,
		Token:      v.RootToken,
		CaCert:     v.CaCert,
		ClientCert: v.ClientCert,
		ClientKey:  v.ClientKey,
	}

	client, err := newClient(conf)
	require.NoError(err)
	require.NotNil(client)
	require.NoError(client.Ping())
	return client
}

// CreateToken creates a new Vault token by calling /auth/token/create on v
// using v.RootToken. See
// https://www.vaultproject.io/api-docs/auth/token#create-token.
func (v *TestVaultServer) CreateToken(t *testing.T, opt ...TestOption) *vault.Secret {
	t.Helper()
	require := require.New(t)
	opts := getTestTokenOpts(t, opt...)

	var period string
	if opts.periodic {
		period = "24h"
		if deadline, ok := t.Deadline(); ok {
			period = time.Until(deadline).String()
		}
	}
	req := &vault.TokenCreateRequest{
		DisplayName: t.Name(),
		NoParent:    opts.orphan,
		Renewable:   &opts.renewable,
		Period:      period,
		Policies:    opts.policies,
	}
	vc := v.client(t).cl
	token, err := vc.Auth().Token().Create(req)
	require.NoError(err)
	require.NotNil(token)

	return token
}

// LookupToken calls /auth/token/lookup on v for token. See
// https://www.vaultproject.io/api-docs/auth/token#lookup-a-token.
func (v *TestVaultServer) LookupToken(t *testing.T, token string) *vault.Secret {
	t.Helper()
	require := require.New(t)
	vc := v.client(t).cl
	secret, err := vc.Auth().Token().Lookup(token)
	require.NoError(err)
	require.NotNil(secret)
	return secret
}
