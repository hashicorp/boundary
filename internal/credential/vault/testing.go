package vault

import (
	"context"
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

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-rootcerts"
	vault "github.com/hashicorp/vault/api"
	"github.com/jinzhu/gorm"
	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCredentialStores creates count number of vault credential stores in
// the provided DB with the provided scope id. If any errors are
// encountered during the creation of the credential stores, the test will
// fail.
func TestCredentialStores(t *testing.T, conn *gorm.DB, wrapper wrapping.Wrapper, scopeId string, count int) []*CredentialStore {
	t.Helper()
	assert, require := assert.New(t), require.New(t)
	w := db.New(conn)

	ctx := context.Background()
	kkms := kms.TestKms(t, conn, wrapper)
	databaseWrapper, err := kkms.GetWrapper(ctx, scopeId, kms.KeyPurposeDatabase)
	assert.NoError(err)
	require.NotNil(databaseWrapper)

	var css []*CredentialStore
	for i := 0; i < count; i++ {
		cs, err := NewCredentialStore(scopeId, fmt.Sprintf("http://vault%d", i), []byte(fmt.Sprintf("vault-token-%s-%d", scopeId, i)))
		assert.NoError(err)
		require.NotNil(cs)
		id, err := newCredentialStoreId()
		assert.NoError(err)
		require.NotEmpty(id)
		cs.PublicId = id

		_, err2 := w.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
			func(_ db.Reader, iw db.Writer) error {
				return iw.Create(ctx, cs)
			},
		)
		require.NoError(err2)

		tokens := testTokens(t, conn, wrapper, scopeId, cs.GetPublicId(), 4)
		// the last token added is the current one.
		cs.outputToken = tokens[3]

		inCert := testClientCert(t, testCaCert(t))
		clientCert, err := NewClientCertificate(inCert.Cert.Cert, inCert.Cert.Key)
		require.NoError(err)
		require.NotEmpty(clientCert)
		clientCert.StoreId = id
		require.NoError(clientCert.encrypt(ctx, databaseWrapper))

		_, err3 := w.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
			func(_ db.Reader, iw db.Writer) error {
				return iw.Create(ctx, clientCert)
			},
		)
		require.NoError(err3)

		cs.clientCert = clientCert
		css = append(css, cs)
	}
	return css
}

// TestCredentialLibraries creates count number of vault credential
// libraries in the provided DB with the provided store id. If any errors
// are encountered during the creation of the credential libraries, the
// test will fail.
func TestCredentialLibraries(t *testing.T, conn *gorm.DB, _ wrapping.Wrapper, storeId string, count int) []*CredentialLibrary {
	t.Helper()
	assert, require := assert.New(t), require.New(t)
	w := db.New(conn)
	var libs []*CredentialLibrary

	for i := 0; i < count; i++ {
		lib, err := NewCredentialLibrary(storeId, fmt.Sprintf("vault/path%d", i))
		assert.NoError(err)
		require.NotNil(lib)
		id, err := newCredentialLibraryId()
		assert.NoError(err)
		require.NotEmpty(id)
		lib.PublicId = id

		ctx := context.Background()
		_, err2 := w.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
			func(_ db.Reader, iw db.Writer) error {
				return iw.Create(ctx, lib)
			},
		)

		require.NoError(err2)
		libs = append(libs, lib)
	}
	return libs
}

// TestLeases creates count number of vault leases in the provided DB with
// the provided library id and session id. If any errors are encountered
// during the creation of the leases , the test will fail.
func TestLeases(t *testing.T, conn *gorm.DB, wrapper wrapping.Wrapper, libraryId, sessionId string, count int) []*Lease {
	t.Helper()
	assert, require := assert.New(t), require.New(t)
	rw := db.New(conn)

	ctx := context.Background()
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(rw, rw, kms)
	assert.NoError(err)
	require.NotNil(repo)

	lib, err := repo.LookupCredentialLibrary(ctx, libraryId)
	assert.NoError(err)
	require.NotNil(lib)

	store, err := repo.LookupCredentialStore(ctx, lib.GetStoreId())
	assert.NoError(err)
	require.NotNil(store)

	token := store.Token()
	require.NotNil(token)

	var leases []*Lease
	for i := 0; i < count; i++ {
		lease, err := newLease(lib.GetPublicId(), sessionId, fmt.Sprintf("vault/lease/%d", i), token.GetTokenHmac(), 5*time.Minute)
		assert.NoError(err)
		require.NotNil(lease)

		id, err := newCredentialId()
		assert.NoError(err)
		require.NotNil(id)
		lease.PublicId = id

		query, queryValues := lease.insertQuery()
		rows, err2 := rw.Exec(ctx, query, queryValues)
		assert.Equal(1, rows)
		assert.NoError(err2)

		leases = append(leases, lease)
	}
	return leases
}

func testTokens(t *testing.T, conn *gorm.DB, wrapper wrapping.Wrapper, scopeId, storeId string, count int) []*Token {
	t.Helper()
	assert, require := assert.New(t), require.New(t)
	w := db.New(conn)

	ctx := context.Background()
	kkms := kms.TestKms(t, conn, wrapper)
	databaseWrapper, err := kkms.GetWrapper(ctx, scopeId, kms.KeyPurposeDatabase)
	assert.NoError(err)
	require.NotNil(databaseWrapper)

	var tokens []*Token
	for i := 0; i < count; i++ {
		inToken, err := newToken(storeId, []byte(fmt.Sprintf("vault-token-%s-%d", storeId, i)), []byte(fmt.Sprintf("accessor-%s-%d", storeId, i)), 5*time.Minute)
		assert.NoError(err)
		require.NotNil(inToken)

		require.NoError(inToken.encrypt(ctx, databaseWrapper))
		query, queryValues := inToken.insertQuery()

		rows, err2 := w.Exec(ctx, query, queryValues)
		assert.Equal(1, rows)
		require.NoError(err2)

		outToken := allocToken()
		require.NoError(w.LookupWhere(ctx, &outToken, "token_hmac = ?", inToken.TokenHmac))
		require.NoError(outToken.decrypt(ctx, databaseWrapper))

		tokens = append(tokens, outToken)
	}
	return tokens
}

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
	ServerCert []byte
	ClientCert []byte
	ClientKey  []byte

	serverCertBundle *testCertBundle
	clientCertBundle *testCertBundle
}

// NewTestVaultServer creates and returns a TestVaultServer.
func NewTestVaultServer(t *testing.T, testTls TestVaultTLS) *TestVaultServer {
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
	t.Cleanup(func() {
		cleanupResource(t, pool, resource)
	})
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
	return server
}

func newTestVaultServerTLS(t *testing.T, testTls TestVaultTLS) *TestVaultServer {
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
	server.serverCertBundle = serverCert
	server.ServerCert = serverCert.Cert.Cert
	server.CaCert = serverCert.CA.Cert

	dataSrcDir := t.TempDir()
	require.NoError(os.Chmod(dataSrcDir, 0o777))

	caCertFn := filepath.Join(dataSrcDir, "ca-certificate.pem")
	require.NoError(ioutil.WriteFile(caCertFn, serverCert.CA.Cert, 0o777))
	certFn := filepath.Join(dataSrcDir, "certificate.pem")
	require.NoError(ioutil.WriteFile(certFn, serverCert.Cert.Cert, 0o777))
	keyFn := filepath.Join(dataSrcDir, "key.pem")
	require.NoError(ioutil.WriteFile(keyFn, serverCert.Cert.Key, 0o777))

	var clientCert *testCertBundle
	if testTls == TestClientTLS {
		template = clientTlsTemplate
		clientCert = testClientCert(t, testCaCert(t))
		server.clientCertBundle = clientCert
		server.ClientCert = clientCert.Cert.Cert
		server.ClientKey = clientCert.Cert.Key
		clientCaCertFn := filepath.Join(dataSrcDir, "client-ca-certificate.pem")
		require.NoError(ioutil.WriteFile(clientCaCertFn, clientCert.CA.Cert, 0o777))
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
		t.FailNow()
	}
	t.Cleanup(func() {
		cleanupResource(t, pool, resource)
	})
	server.Addr = fmt.Sprintf("https://localhost:%s", resource.GetPort("8200/tcp"))

	vConfig := vault.DefaultConfig()
	vConfig.Address = server.Addr

	clientTLSConfig := vConfig.HttpClient.Transport.(*http.Transport).TLSClientConfig
	rootConfig := &rootcerts.Config{
		CACertificate: serverCert.CA.Cert,
	}

	require.NoError(rootcerts.ConfigureTLS(clientTLSConfig, rootConfig))

	if testTls == TestClientTLS {
		vaultClientCert, err := tls.X509KeyPair(server.ClientCert, server.ClientKey)
		require.NoError(err)
		clientTLSConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &vaultClientCert, nil
		}
	}

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
	return server
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

func (tc *testCert) ClientCertificate(t *testing.T) *ClientCertificate {
	t.Helper()
	c, err := NewClientCertificate(tc.Cert, tc.Key)
	require.NoError(t, err)
	return c
}

type testCertBundle struct {
	CA   *testCert
	Cert *testCert
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
		CA:   ca,
		Cert: serverCert,
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

	clientCert := &testCert{
		Cert:        pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}),
		Key:         pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: k}),
		certificate: c,
		priv:        priv,
	}

	return &testCertBundle{
		CA:   ca,
		Cert: clientCert,
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
func TestOrphanToken(b bool) TestOption {
	return func(t *testing.T, o *testOptions) {
		t.Helper()
		o.orphan = b
	}
}

// TestPeriodicToken sets the token periodic option to b.
// The periodic option is true by default.
func TestPeriodicToken(b bool) TestOption {
	return func(t *testing.T, o *testOptions) {
		t.Helper()
		o.periodic = b
	}
}

// TestRenewableToken sets the token renewable option to b.
// The renewable option is true by default.
func TestRenewableToken(b bool) TestOption {
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
