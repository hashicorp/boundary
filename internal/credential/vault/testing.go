package vault

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/scheduler"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	vault "github.com/hashicorp/vault/api"
	"github.com/jinzhu/gorm"
	_ "github.com/lib/pq"
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
		lib, err := NewCredentialLibrary(storeId, fmt.Sprintf("vault/path%d", i), WithMethod(MethodGet))
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

// TestCredentials creates count number of vault credentials in the provided DB with
// the provided library id and session id. If any errors are encountered
// during the creation of the credentials , the test will fail.
func TestCredentials(t *testing.T, conn *gorm.DB, wrapper wrapping.Wrapper, libraryId, sessionId string, count int, opt ...TestOption) []*Credential {
	t.Helper()

	opts := getTestOpts(t, opt...)
	assert, require := assert.New(t), require.New(t)
	rw := db.New(conn)

	ctx := context.Background()
	kms := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	repo, err := NewRepository(rw, rw, kms, sche)
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

	var credentials []*Credential
	for i := 0; i < count; i++ {
		credential, err := newCredential(lib.GetPublicId(), sessionId, fmt.Sprintf("vault/credential/%d", i), token.GetTokenHmac(), 5*time.Minute)
		assert.NoError(err)
		require.NotNil(credential)

		id, err := newCredentialId()
		assert.NoError(err)
		require.NotNil(id)
		credential.PublicId = id
		credential.IsRenewable = opts.renewable

		query, queryValues := credential.insertQuery()
		rows, err2 := rw.Exec(ctx, query, queryValues)
		assert.Equal(1, rows)
		assert.NoError(err2)

		credentials = append(credentials, credential)
	}
	return credentials
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

func getTestOpts(t *testing.T, opt ...TestOption) testOptions {
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
	orphan        bool
	periodic      bool
	renewable     bool
	policies      []string
	mountPath     string
	roleName      string
	vaultTLS      TestVaultTLS
	dockerNetwork bool
}

func getDefaultTestOptions(t *testing.T) testOptions {
	t.Helper()
	return testOptions{
		orphan:        true,
		periodic:      true,
		renewable:     true,
		policies:      []string{"default"},
		mountPath:     "",
		roleName:      "boundary",
		vaultTLS:      TestNoTLS,
		dockerNetwork: false,
	}
}

// WithPolicies sets the polices to attach to a token. The default policy
// attached to tokens is 'default'.
func WithPolicies(p []string) TestOption {
	return func(t *testing.T, o *testOptions) {
		t.Helper()
		o.policies = p
	}
}

// WithDockerNetwork sets the option to create docker network when creating
// a Vault test server. The default is to not create a docker network.
func WithDockerNetwork(b bool) TestOption {
	return func(t *testing.T, o *testOptions) {
		t.Helper()
		o.dockerNetwork = b
	}
}

// WithTestVaultTLS sets the Vault TLS option.
// TestNoTLS is the default TLS option.
func WithTestVaultTLS(s TestVaultTLS) TestOption {
	return func(t *testing.T, o *testOptions) {
		t.Helper()
		o.vaultTLS = s
	}
}

// WithTestMountPath sets the mount path option to p.
func WithTestMountPath(p string) TestOption {
	return func(t *testing.T, o *testOptions) {
		t.Helper()
		p = strings.TrimSpace(p)
		if p != "" {
			p = strings.TrimRight(p, "/") + "/"
		}
		o.mountPath = p
	}
}

// WithTestRoleName sets the roleName name to n.
// The default role name is boundary.
func WithTestRoleName(n string) TestOption {
	return func(t *testing.T, o *testOptions) {
		t.Helper()
		n = strings.TrimSpace(n)
		if n == "" {
			n = "boundary"
		}
		o.roleName = n
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

// TestRenewable sets the token renewable option to b.
// The renewable option is true by default.
func TestRenewable(b bool) TestOption {
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
	require.NoError(client.ping())
	return client
}

// CreateToken creates a new Vault token by calling /auth/token/create on v
// using v.RootToken. See
// https://www.vaultproject.io/api-docs/auth/token#create-token.
func (v *TestVaultServer) CreateToken(t *testing.T, opt ...TestOption) *vault.Secret {
	t.Helper()
	require := require.New(t)
	opts := getTestOpts(t, opt...)

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

func (v *TestVaultServer) addPolicy(t *testing.T, name string, mountPath string) {
	const template = `
		path "%s*" {
			capabilities = ["create", "read", "update", "delete", "list"]
		}`

	t.Helper()
	require := require.New(t)
	policy := fmt.Sprintf(template, mountPath)
	vc := v.client(t).cl
	require.NoError(vc.Sys().PutPolicy(name, policy))
}

// MountPKI mounts the Vault PKI secret engine and initializes it by
// generating a root certificate authority and creating a default role on
// the mount. The root CA is returned.
//
// The default mount path is pki and the default role name is boundary.
// WithTestMountPath and WithTestRoleName are the only test options
// supported.
//
// MountPKI also adds a Vault policy named 'pki' to v and adds it to the
// standard set of polices attached to tokens created with v.CreateToken.
// The policy is defined as:
//
//   path "mountPath/*" {
//     capabilities = ["create", "read", "update", "delete", "list"]
//   }
func (v *TestVaultServer) MountPKI(t *testing.T, opt ...TestOption) *vault.Secret {
	t.Helper()
	require := require.New(t)
	opts := getTestOpts(t, opt...)
	vc := v.client(t).cl

	// Mount PKI
	maxTTL := 24 * time.Hour
	if deadline, ok := t.Deadline(); ok {
		maxTTL = time.Until(deadline) * 2
	}

	defaultTTL := maxTTL / 2
	t.Logf("maxTTL: %s, defaultTTL: %s", maxTTL, defaultTTL)
	mountInput := &vault.MountInput{
		Type:        "pki",
		Description: t.Name(),
		Config: vault.MountConfigInput{
			DefaultLeaseTTL: defaultTTL.String(),
			MaxLeaseTTL:     maxTTL.String(),
		},
	}
	mountPath := opts.mountPath
	if mountPath == "" {
		mountPath = "pki/"
	}
	require.NoError(vc.Sys().Mount(mountPath, mountInput))
	v.addPolicy(t, "pki", mountPath)

	// Generate a root CA
	caPath := path.Join(mountPath, "root/generate/internal")
	caOptions := map[string]interface{}{
		"common_name": t.Name(),
		"ttl":         maxTTL.String(),
	}
	s, err := vc.Logical().Write(caPath, caOptions)
	require.NoError(err)
	require.NotEmpty(s)

	// Create default role
	rolePath := path.Join(mountPath, "roles", opts.roleName)
	roleOptions := map[string]interface{}{
		"allow_any_name": true,
		"ttl":            defaultTTL.String(),
	}
	_, err = vc.Logical().Write(rolePath, roleOptions)
	require.NoError(err)

	return s
}

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

	pool              interface{}
	vaultContainer    interface{}
	network           interface{}
	postgresContainer interface{}
}

// NewTestVaultServer creates and returns a TestVaultServer. Some Vault
// secret engines require the Vault server be created with a docker
// network. Check the Mount method for the Vault secret engine to see if a
// docker network is required.
//
// WithTestVaultTLS and WithDockerNetwork are the only valid options.
// Setting the WithDockerNetwork option can significantly increase the
// amount of time required for a test to run.
func NewTestVaultServer(t *testing.T, opt ...TestOption) *TestVaultServer {
	t.Helper()
	return newVaultServer(t, opt...)
}

// MountDatabase starts a PostgreSQL database in a docker container then
// mounts the Vault database secrets engine and configures it to issue
// credentials for the database.
//
// MountDatabase also adds a Vault policy named 'database' to v and adds it
// to the standard set of polices attached to tokens created with
// v.CreateToken. The policy is defined as:
//
//   path "mountPath/*" {
//     capabilities = ["create", "read", "update", "delete", "list"]
//   }
func (v *TestVaultServer) MountDatabase(t *testing.T, opt ...TestOption) {
	t.Helper()
	mountDatabase(t, v, opt...)
}
