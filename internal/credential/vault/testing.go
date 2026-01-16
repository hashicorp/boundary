// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

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
	mrand "math/rand"
	"net"
	"net/http"
	"path"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/scheduler"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	vault "github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCredentialStore creates a vault credential store in the provided DB with
// the provided project, vault address, token, and accessor and any values passed
// in through the Options vargs.  If any errors are encountered during the
// creation of the store, the test will fail.
func TestCredentialStore(t testing.TB, conn *db.DB, wrapper wrapping.Wrapper, projectId, vaultAddr, vaultToken, accessor string, opts ...Option) *CredentialStore {
	t.Helper()
	ctx := context.Background()
	kmsCache := kms.TestKms(t, conn, wrapper)
	w := db.New(conn)

	databaseWrapper, err := kmsCache.GetWrapper(ctx, projectId, kms.KeyPurposeDatabase)
	assert.NoError(t, err)
	require.NotNil(t, databaseWrapper)

	cs, err := NewCredentialStore(projectId, vaultAddr, []byte(vaultToken), opts...)
	assert.NoError(t, err)
	require.NotNil(t, cs)
	id, err := newCredentialStoreId(ctx)
	assert.NoError(t, err)
	require.NotEmpty(t, id)
	cs.PublicId = id

	_, err2 := w.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, iw db.Writer) error {
			require.NoError(t, iw.Create(ctx, cs))
			cert := cs.clientCert
			if cert != nil {
				cert.StoreId = cs.GetPublicId()
				require.NoError(t, cert.encrypt(ctx, databaseWrapper))
				require.NoError(t, iw.Create(ctx, cert))
			}
			return nil
		},
	)
	require.NoError(t, err2)

	cs.outputToken = createTestToken(t, conn, wrapper, projectId, id, vaultToken, accessor)

	return cs
}

// TestCredentialStores creates count number of vault credential stores in
// the provided DB with the provided project id. If any errors are
// encountered during the creation of the credential stores, the test will
// fail.
func TestCredentialStores(t testing.TB, conn *db.DB, wrapper wrapping.Wrapper, projectId string, count int) []*CredentialStore {
	t.Helper()
	ctx := context.Background()
	kmsCache := kms.TestKms(t, conn, wrapper)
	w := db.New(conn)

	databaseWrapper, err := kmsCache.GetWrapper(ctx, projectId, kms.KeyPurposeDatabase)
	assert.NoError(t, err)
	require.NotNil(t, databaseWrapper)

	var css []*CredentialStore
	for i := 0; i < count; i++ {
		cs := TestCredentialStore(t, conn, wrapper, projectId, fmt.Sprintf("http://vault%d", i), fmt.Sprintf("vault-token-%s-%d", projectId, i), fmt.Sprintf("accessor-%s-%d", projectId, i))

		inCert := testClientCert(t, testCaCert(t))
		clientCert, err := NewClientCertificate(ctx, inCert.Cert.Cert, inCert.Cert.Key)
		require.NoError(t, err)
		require.NotEmpty(t, clientCert)
		clientCert.StoreId = cs.GetPublicId()
		require.NoError(t, clientCert.encrypt(ctx, databaseWrapper))

		_, err3 := w.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
			func(_ db.Reader, iw db.Writer) error {
				return iw.Create(ctx, clientCert)
			},
		)
		require.NoError(t, err3)

		cs.clientCert = clientCert
		css = append(css, cs)
	}
	return css
}

// TestCredentialLibraries creates count number of vault credential
// libraries in the provided DB with the provided store id. If any errors
// are encountered during the creation of the credential libraries, the
// test will fail.
func TestCredentialLibraries(t testing.TB, conn *db.DB, _ wrapping.Wrapper, storeId string, credType globals.CredentialType, count int) []*CredentialLibrary {
	t.Helper()
	ctx := context.Background()
	assert, require := assert.New(t), require.New(t)
	w := db.New(conn)
	var libs []*CredentialLibrary

	for i := 0; i < count; i++ {
		opts := []Option{WithMethod(MethodGet)}
		if credType != "" {
			opts = append(opts, WithCredentialType(credType))
		}
		lib, err := NewCredentialLibrary(storeId, fmt.Sprintf("vault/path%d", i), opts...)
		assert.NoError(err)
		require.NotNil(lib)
		id, err := newCredentialLibraryId(ctx)
		assert.NoError(err)
		require.NotEmpty(id)
		lib.PublicId = id

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

// TestSSHCertificateCredentialLibraries creates count number of vault ssh
// certificate credential libraries in the provided DB with the provided store
// id. If any errors are encountered during the creation of the credential
// libraries, the test will fail.
func TestSSHCertificateCredentialLibraries(t testing.TB, conn *db.DB, _ wrapping.Wrapper, storeId string, count int) []*SSHCertificateCredentialLibrary {
	t.Helper()
	ctx := context.Background()
	assert, require := assert.New(t), require.New(t)
	w := db.New(conn)
	var libs []*SSHCertificateCredentialLibrary

	for i := 0; i < count; i++ {
		lib, err := NewSSHCertificateCredentialLibrary(storeId, fmt.Sprintf("ssh/sign/role-%d", i), "username", WithKeyType(KeyTypeEd25519))
		assert.NoError(err)
		require.NotNil(lib)
		id, err := newSSHCertificateCredentialLibraryId(ctx)
		assert.NoError(err)
		require.NotEmpty(id)
		lib.PublicId = id

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

// TestLdapCredentialLibraries creates `count` number of Vault LDAP credential
// libraries in the provided db with the provided credential store. If any
// errors are encountered, the test will fail.
func TestLdapCredentialLibraries(t testing.TB, conn *db.DB, _ wrapping.Wrapper, storeId string, count int) []*LdapCredentialLibrary {
	t.Helper()
	w := db.New(conn)

	var libs []*LdapCredentialLibrary
	for i := range count {
		var staticOrDynamic string
		switch mrand.Intn(2) {
		case 0:
			staticOrDynamic = "static-cred"
		case 1:
			staticOrDynamic = "creds"
		}

		lib, err := NewLdapCredentialLibrary(storeId, fmt.Sprintf("ldap/%s/role-%d", staticOrDynamic, i))
		require.NoError(t, err)
		require.NotNil(t, lib)

		libId, err := newLdapCredentialLibraryId(t.Context())
		require.NoError(t, err)
		require.NotEmpty(t, libId)

		lib.PublicId = libId
		_, err = w.DoTx(t.Context(), db.StdRetryCnt, db.ExpBackoff{},
			func(_ db.Reader, w db.Writer) error {
				return w.Create(t.Context(), lib)
			},
		)
		require.NoError(t, err)
		libs = append(libs, lib)
	}

	return libs
}

// TestCredentials creates count number of vault credentials in the provided DB with
// the provided library id and session id. If any errors are encountered
// during the creation of the credentials, the test will fail.
func TestCredentials(t testing.TB, conn *db.DB, wrapper wrapping.Wrapper, libraryId, sessionId string, count int) []*Credential {
	t.Helper()
	assert, require := assert.New(t), require.New(t)
	rw := db.New(conn)

	ctx := context.Background()
	kms := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	repo, err := NewRepository(ctx, rw, rw, kms, sche)
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
		credential, err := newCredential(ctx, lib.GetPublicId(), fmt.Sprintf("vault/credential/%d", i), token.GetTokenHmac(), 5*time.Minute)
		assert.NoError(err)
		require.NotNil(credential)

		id, err := newCredentialId(ctx)
		assert.NoError(err)
		require.NotNil(id)
		credential.PublicId = id

		query, queryValues := insertQuery(credential, sessionId)
		rows, err2 := rw.Exec(ctx, query, queryValues)
		assert.Equal(1, rows)
		assert.NoError(err2)

		credentials = append(credentials, credential)
	}
	return credentials
}

func createTestToken(t testing.TB, conn *db.DB, wrapper wrapping.Wrapper, projectId, storeId, token, accessor string) *Token {
	t.Helper()
	w := db.New(conn)
	ctx := context.Background()
	kkms := kms.TestKms(t, conn, wrapper)
	databaseWrapper, err := kkms.GetWrapper(ctx, projectId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	inToken, err := newToken(ctx, storeId, []byte(token), []byte(accessor), 5*time.Minute)
	assert.NoError(t, err)
	require.NotNil(t, inToken)

	require.NoError(t, inToken.encrypt(ctx, databaseWrapper))
	query, queryValues := inToken.insertQuery()

	rows, err2 := w.Exec(ctx, query, queryValues)
	assert.Equal(t, 1, rows)
	require.NoError(t, err2)

	return inToken
}

func testTokens(t testing.TB, conn *db.DB, wrapper wrapping.Wrapper, projectId, storeId string, count int) []*Token {
	t.Helper()
	assert, require := assert.New(t), require.New(t)
	w := db.New(conn)

	ctx := context.Background()
	kkms := kms.TestKms(t, conn, wrapper)
	databaseWrapper, err := kkms.GetWrapper(ctx, projectId, kms.KeyPurposeDatabase)
	assert.NoError(err)
	require.NotNil(databaseWrapper)

	r := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	var tokens []*Token
	for i := 0; i < count; i++ {
		num := r.Int31()
		inToken := createTestToken(t, conn, wrapper, projectId, storeId, fmt.Sprintf("vault-token-%s-%d-%v", storeId, i, num), fmt.Sprintf("accessor-%s-%d-%v", storeId, i, num))
		outToken := allocToken()
		require.NoError(w.LookupWhere(ctx, &outToken, "token_hmac = ?", []any{inToken.TokenHmac}))
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

func (tc *testCert) ClientCertificate(t testing.TB) *ClientCertificate {
	t.Helper()
	c, err := NewClientCertificate(context.Background(), tc.Cert, tc.Key)
	require.NoError(t, err)
	return c
}

type testCertBundle struct {
	CA   *testCert
	Cert *testCert
}

// testCaCert will generate a test x509 CA cert.
func testCaCert(t testing.TB) *testCert {
	t.Helper()
	require := require.New(t)

	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(err)

	// ECDSA, ED25519 and RSA subject keys should have the DigitalSignature
	// KeyUsage bits set in the x509.Certificate template
	keyUsage := x509.KeyUsageDigitalSignature

	notBefore, notAfter := time.Now(), time.Now().Add(24*time.Hour)
	if t, ok := t.(*testing.T); ok {
		if deadline, ok := t.Deadline(); ok {
			notAfter = deadline
		}
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
func testServerCert(t testing.TB, ca *testCert, opt ...TestOption) *testCertBundle {
	t.Helper()
	require := require.New(t)

	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(err)

	// ECDSA, ED25519 and RSA subject keys should have the DigitalSignature
	// KeyUsage bits set in the x509.Certificate template
	keyUsage := x509.KeyUsageDigitalSignature

	notBefore, notAfter := time.Now(), time.Now().Add(24*time.Hour)
	if t, ok := t.(*testing.T); ok {
		if deadline, ok := t.Deadline(); ok {
			notAfter = deadline
		}
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

	opts := getTestOpts(t, opt...)
	for _, h := range opts.serverCertHostNames {
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
func testClientCert(t testing.TB, ca *testCert, opt ...TestOption) *testCertBundle {
	t.Helper()
	require := require.New(t)

	var err error
	opts := getTestOpts(t, opt...)
	priv := opts.clientKey
	if priv == nil {
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		require.NoError(err)
	}

	// ECDSA, ED25519 and RSA subject keys should have the DigitalSignature
	// KeyUsage bits set in the x509.Certificate template
	keyUsage := x509.KeyUsageDigitalSignature

	notBefore, notAfter := time.Now(), time.Now().Add(24*time.Hour)
	if t, ok := t.(*testing.T); ok {
		if deadline, ok := t.Deadline(); ok {
			notAfter = deadline
		}
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

func getTestOpts(t testing.TB, opt ...TestOption) testOptions {
	t.Helper()
	opts := getDefaultTestOptions(t)
	for _, o := range opt {
		o(t, &opts)
	}
	return opts
}

// TestOption - how Options are passed as arguments.
type TestOption func(testing.TB, *testOptions)

// options = how options are represented
type testOptions struct {
	orphan              bool
	periodic            bool
	renewable           bool
	policies            []string
	allowedExtensions   []string
	mountPath           string
	roleName            string
	vaultTLS            TestVaultTLS
	dockerNetwork       bool
	skipCleanup         bool
	tokenPeriod         time.Duration
	clientKey           *ecdsa.PrivateKey
	vaultVersion        string
	serverCertHostNames []string
	bindDn              string
	bindPass            string
	ldapUrl             string
	ldapRootDomain      string
}

func getDefaultTestOptions(t testing.TB) testOptions {
	t.Helper()
	defaultPeriod := 24 * time.Hour
	if t, ok := t.(*testing.T); ok {
		if deadline, ok := t.Deadline(); ok {
			defaultPeriod = time.Until(deadline)
		}
	}

	return testOptions{
		orphan:              true,
		periodic:            true,
		renewable:           true,
		policies:            []string{"default", "boundary-controller"},
		mountPath:           "",
		roleName:            "boundary",
		vaultTLS:            TestNoTLS,
		dockerNetwork:       false,
		tokenPeriod:         defaultPeriod,
		serverCertHostNames: []string{"localhost", "127.0.0.1", "::1"},
	}
}

// WithTokenPeriod sets the period value in a vault.TokenCreateRequest when
// the token being requested is a periodic token. The default token period
// is the value of t.Deadline() or 24 hours if
// t.Deadline() is nil.
func WithTokenPeriod(d time.Duration) TestOption {
	return func(t testing.TB, o *testOptions) {
		t.Helper()
		o.tokenPeriod = d
	}
}

// WithPolicies sets the polices to attach to a token. The default policy
// attached to tokens is 'default'.
func WithPolicies(p []string) TestOption {
	return func(t testing.TB, o *testOptions) {
		t.Helper()
		o.policies = p
	}
}

// WithDockerNetwork sets the option to create docker network when creating
// a Vault test server. The default is to not create a docker network.
func WithDockerNetwork(b bool) TestOption {
	return func(t testing.TB, o *testOptions) {
		t.Helper()
		o.dockerNetwork = b
	}
}

// WithTestVaultTLS sets the Vault TLS option.
// TestNoTLS is the default TLS option.
func WithTestVaultTLS(s TestVaultTLS) TestOption {
	return func(t testing.TB, o *testOptions) {
		t.Helper()
		o.vaultTLS = s
	}
}

// WithServerCertHostNames sets the host names or IP address to attach to
// the test server's TLS certificate. The default host name attached to the
// test server's TLS certificate is 'localhost'.
func WithServerCertHostNames(h []string) TestOption {
	return func(t testing.TB, o *testOptions) {
		t.Helper()
		o.serverCertHostNames = h
	}
}

// WithClientKey sets the private key that will be used to generate the
// client certificate.  The option is only valid when used together with TestClientTLS.
func WithClientKey(k *ecdsa.PrivateKey) TestOption {
	return func(t testing.TB, o *testOptions) {
		t.Helper()
		o.clientKey = k
	}
}

// WithTestMountPath sets the mount path option to p.
func WithTestMountPath(p string) TestOption {
	return func(t testing.TB, o *testOptions) {
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
	return func(t testing.TB, o *testOptions) {
		t.Helper()
		n = strings.TrimSpace(n)
		if n == "" {
			n = "boundary"
		}
		o.roleName = n
	}
}

// WithDontCleanUp causes the resource created to not
// be automaticaly cleaned up at the end of the test run.
func WithDontCleanUp() TestOption {
	return func(t testing.TB, o *testOptions) {
		t.Helper()
		o.skipCleanup = true
	}
}

// WithVaultVersion sets the version of vault that will be started.
// defaults to the value stored in vault.supported.DefaultVaultVersion
func WithVaultVersion(s string) TestOption {
	return func(t testing.TB, o *testOptions) {
		t.Helper()
		o.vaultVersion = s
	}
}

// WithAllowedExtension tells vault to allow a specific SSH extension
// to be used by vault's ssh secrets engine
func WithAllowedExtension(e string) TestOption {
	return func(t testing.TB, o *testOptions) {
		t.Helper()
		o.allowedExtensions = append(o.allowedExtensions, e)
	}
}

// WithBindDn sets the distinguished name to be used by the Vault LDAP secrets
// engine.
func WithBindDn(dn string) TestOption {
	return func(t testing.TB, o *testOptions) {
		t.Helper()
		o.bindDn = dn
	}
}

// WithBindPass sets the password to be used by the Vault LDAP secrets engine.
// It is also used to set the admin user password in the LDAP server.
func WithBindPass(p string) TestOption {
	return func(t testing.TB, o *testOptions) {
		t.Helper()
		o.bindPass = p
	}
}

// WithLdapUrl sets the URL to be used by the Vault LDAP secrets engine.
func WithLdapUrl(u string) TestOption {
	return func(t testing.TB, o *testOptions) {
		t.Helper()
		o.ldapUrl = u
	}
}

// WithLdapRootDomain controls the LDAP server's root domain.
func WithLdapRootDomain(d string) TestOption {
	return func(t testing.TB, o *testOptions) {
		t.Helper()
		o.ldapRootDomain = d
	}
}

// TestOrphanToken sets the token orphan option to b.
// The orphan option is true by default.
func TestOrphanToken(b bool) TestOption {
	return func(t testing.TB, o *testOptions) {
		t.Helper()
		o.orphan = b
	}
}

// TestPeriodicToken sets the token periodic option to b.
// The periodic option is true by default.
func TestPeriodicToken(b bool) TestOption {
	return func(t testing.TB, o *testOptions) {
		t.Helper()
		o.periodic = b
	}
}

// TestRenewableToken sets the token renewable option to b.
// The renewable option is true by default.
func TestRenewableToken(b bool) TestOption {
	return func(t testing.TB, o *testOptions) {
		t.Helper()
		o.renewable = b
	}
}

// TestClientConfig returns a client config, using the
// provided Vault Server and token
func TestClientConfig(v *TestVaultServer, token string) *clientConfig {
	clientConfig := &clientConfig{
		Addr:       v.Addr,
		Token:      TokenSecret(token),
		CaCert:     v.CaCert,
		ClientCert: v.ClientCert,
		ClientKey:  v.ClientKey,
	}

	return clientConfig
}

func (v *TestVaultServer) client(t testing.TB) *client {
	t.Helper()
	return v.ClientUsingToken(t, v.RootToken)
}

func (v *TestVaultServer) ClientUsingToken(t testing.TB, token string) *client {
	t.Helper()
	ctx := context.Background()
	require := require.New(t)
	conf := &clientConfig{
		Addr:          v.Addr,
		Token:         TokenSecret(token),
		CaCert:        v.CaCert,
		ClientCert:    v.ClientCert,
		ClientKey:     v.ClientKey,
		TlsServerName: v.TlsServerName,
		TlsSkipVerify: v.TlsSkipVerify,
	}

	client, err := newClient(ctx, conf)
	require.NoError(err)
	require.NotNil(client)
	require.NoError(client.ping(ctx))
	return client
}

// CreateToken creates a new Vault token by calling /auth/token/create on v
// using v.RootToken. It returns the vault secret containing the token and
// the token itself. See
// https://www.vaultproject.io/api-docs/auth/token#create-token.
func (v *TestVaultServer) CreateToken(t testing.TB, opt ...TestOption) (*vault.Secret, string) {
	t.Helper()
	require := require.New(t)
	opts := getTestOpts(t, opt...)

	var period string
	if opts.periodic {
		period = opts.tokenPeriod.String()
	}
	req := &vault.TokenCreateRequest{
		DisplayName: t.Name(),
		NoParent:    opts.orphan,
		Renewable:   &opts.renewable,
		Period:      period,
		Policies:    opts.policies,
	}
	vc := v.client(t).cl
	secret, err := vc.Auth().Token().Create(req)
	require.NoError(err)
	require.NotNil(secret)
	token, err := secret.TokenID()
	require.NoError(err)
	require.NotNil(token)

	return secret, token
}

// RevokeToken calls /auth/token/revoke-self on v for the token. See
// https://www.vaultproject.io/api-docs/auth/token#revoke-a-token-self.
func (v *TestVaultServer) RevokeToken(t testing.TB, token string) {
	t.Helper()
	require := require.New(t)
	vc := v.client(t).cl
	vc.SetToken(token)
	err := vc.Auth().Token().RevokeSelf("")
	require.NoError(err)
}

// LookupToken calls /auth/token/lookup on v for the token. See
// https://www.vaultproject.io/api-docs/auth/token#lookup-a-token.
func (v *TestVaultServer) LookupToken(t testing.TB, token string) *vault.Secret {
	t.Helper()
	require := require.New(t)
	vc := v.client(t).cl
	secret, err := vc.Auth().Token().Lookup(token)
	require.NoError(err)
	require.NotNil(secret)
	return secret
}

// VerifyTokenInvalid calls /auth/token/lookup on v for the token. It expects the lookup to
// fail with a StatusForbidden.  See
// https://www.vaultproject.io/api-docs/auth/token#lookup-a-token.
func (v *TestVaultServer) VerifyTokenInvalid(t testing.TB, token string) {
	t.Helper()
	require, assert := require.New(t), assert.New(t)
	vc := v.client(t).cl
	secret, err := vc.Auth().Token().Lookup(token)
	require.Error(err)
	require.Nil(secret)

	// Verify error was forbidden
	var respErr *vault.ResponseError
	require.True(errors.As(err, &respErr))
	assert.Equal(http.StatusForbidden, respErr.StatusCode)
}

// LookupLease calls the /sys/leases/lookup Vault endpoint and returns
// the vault.Secret response.  See
// https://www.vaultproject.io/api-docs/system/leases#read-lease.
func (v *TestVaultServer) LookupLease(t testing.TB, leaseId string) *vault.Secret {
	t.Helper()
	require := require.New(t)
	vc := v.client(t).cl
	credData := map[string]any{"lease_id": leaseId}
	secret, err := vc.Logical().Write("sys/leases/lookup", credData)
	require.NoError(err)
	require.NotNil(secret)
	return secret
}

func (v *TestVaultServer) addPolicy(t testing.TB, name string, pc pathCapabilities) {
	t.Helper()
	require := require.New(t)
	policy := pc.vaultPolicy()
	require.NotEmpty(policy)
	vc := v.client(t).cl
	require.NoError(vc.Sys().PutPolicy(name, policy))
}

// MountSSH mounts the Vault SSH secret engine and initializes it by
// generating a root certificate authority and creating a default role on
// the mount. The root CA is returned.
//
// The default mount path is ssh and the default role name is boundary.
// WithTestMountPath, WithTestRoleName, and WithAllowedExtension are the
// test options supported. extensions are combined into allowed_extensions.
// allowed_extensions defaults to "*" (allow all)
// The role is defined as:
//
//	{
//		"key_type": "ca",
//		"allowed_users": "*",
//		"allowed_extensions": "*",
//		"allow_user_certificates": true,
//		"ttl": "12h0m0s"
//	}
//
// MountSSH also adds a Vault policy named 'ssh' to v and adds it to the
// standard set of polices attached to tokens created with v.CreateToken.
// The policy is defined as:
//
//	path "mountPath/*" {
//	  capabilities = ["create", "read", "update", "delete", "list"]
//	}
func (v *TestVaultServer) MountSSH(t testing.TB, opt ...TestOption) *vault.Secret {
	require := require.New(t)
	opts := getTestOpts(t, opt...)
	vc := v.client(t).cl

	// Mount SSH
	maxTTL := 24 * time.Hour
	if t, ok := t.(*testing.T); ok {
		if deadline, ok := t.Deadline(); ok {
			maxTTL = time.Until(deadline) * 2
		}
	}

	defaultTTL := maxTTL / 2
	t.Logf("maxTTL: %s, defaultTTL: %s", maxTTL, defaultTTL)
	mountInput := &vault.MountInput{
		Type:        "ssh",
		Description: t.Name(),
		Config: vault.MountConfigInput{
			DefaultLeaseTTL: defaultTTL.String(),
			MaxLeaseTTL:     maxTTL.String(),
		},
	}
	mountPath := opts.mountPath
	if mountPath == "" {
		mountPath = "ssh/"
	}
	// this is the call that actually enables the secrets engine
	require.NoError(vc.Sys().Mount(mountPath, mountInput))

	policyPath := fmt.Sprintf("%s*", mountPath)
	pc := pathCapabilities{
		policyPath: createCapability | readCapability | updateCapability | deleteCapability | listCapability,
	}
	v.addPolicy(t, "ssh", pc)

	// Generate a root CA
	caPath := path.Join(mountPath, "config/ca")
	caOptions := map[string]any{
		"generate_signing_key": true,
	}
	s, err := vc.Logical().Write(caPath, caOptions)
	require.NoError(err)
	require.NotEmpty(s)

	// Create default role
	rolePath := path.Join(mountPath, "roles", opts.roleName)
	allowExtensions := "*"
	if len(opts.allowedExtensions) > 0 {
		allowExtensions = strings.Join(opts.allowedExtensions, ",")
	}
	roleOptions := map[string]any{
		"key_type":                "ca",
		"allowed_users":           "*",
		"allowed_extensions":      allowExtensions,
		"allow_user_certificates": true,
		"ttl":                     defaultTTL.String(),
	}
	_, err = vc.Logical().Write(rolePath, roleOptions)
	require.NoError(err)

	return s
}

// MountLdap mounts the Vault LDAP secrets engine on a Vault instance and
// initializes it.
//
// Supported options include:
//   - WithTestMountPath: Sets the mount path. Defaults to "ldap".
//   - WithBindDn: Sets the BindDN to be used by the Vault LDAP secrets engine.
//     Defaults to "cn=admin,dc=example,dc=org".
//   - WithBindPass: Sets the password to be used by the Vault LDAP secrets
//     engine. Defaults to "admin".
//   - WithLdapUrl: Sets the URL of the LDAP server to be used by the Vault LDAP
//     secrets engine. Defaults to "ldap://ldap".
//
// MountLdap also adds a Vault policy named 'ldap' to the standard set of
// policies attached to tokens created with v.CreateToken. The policy is defined
// as:
//
//	path "<ldapMountPath>/*" {
//	  capabilities = ["create", "read", "update", "delete", "list"]
//	}
func (v *TestVaultServer) MountLdap(t testing.TB, opt ...TestOption) {
	require := require.New(t)
	opts := getTestOpts(t, opt...)
	vc := v.client(t).cl

	maxTTL := 24 * time.Hour
	if t, ok := t.(*testing.T); ok {
		if deadline, ok := t.Deadline(); ok {
			maxTTL = time.Until(deadline) * 2
		}
	}

	defaultTTL := maxTTL / 2
	mountInput := &vault.MountInput{
		Type:        "ldap",
		Description: t.Name(),
		Config: vault.MountConfigInput{
			DefaultLeaseTTL: defaultTTL.String(),
			MaxLeaseTTL:     maxTTL.String(),
		},
	}
	mountPath := opts.mountPath
	if mountPath == "" {
		mountPath = "ldap/"
	}
	require.True(mountPath[len(mountPath)-1] == '/', "mount path must end with a slash")
	require.NoError(vc.Sys().Mount(mountPath, mountInput))

	policyPath := fmt.Sprintf("%s*", mountPath)
	pc := pathCapabilities{
		policyPath: createCapability | readCapability | updateCapability | deleteCapability | listCapability,
	}
	v.addPolicy(t, "ldap", pc)

	// Create and write LDAP server config
	bindDn := opts.bindDn
	if bindDn == "" {
		bindDn = "cn=admin,dc=example,dc=org"
	}
	bindPass := opts.bindPass
	if bindPass == "" {
		bindPass = "admin"
	}
	url := opts.ldapUrl
	if url == "" {
		url = "ldap://ldap"
	}
	ldapConfig := map[string]any{
		"binddn":   bindDn,
		"bindpass": bindPass,
		"url":      url,
	}
	_, err := vc.Logical().Write(path.Join(mountPath, "config"), ldapConfig)
	require.NoError(err)
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
//	path "mountPath/*" {
//	  capabilities = ["create", "read", "update", "delete", "list"]
//	}
func (v *TestVaultServer) MountPKI(t testing.TB, opt ...TestOption) *vault.Secret {
	t.Helper()
	require := require.New(t)
	opts := getTestOpts(t, opt...)
	vc := v.client(t).cl

	// Mount PKI
	maxTTL := 24 * time.Hour
	if t, ok := t.(*testing.T); ok {
		if deadline, ok := t.Deadline(); ok {
			maxTTL = time.Until(deadline) * 2
		}
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
	policyPath := fmt.Sprintf("%s*", mountPath)
	pc := pathCapabilities{
		policyPath: createCapability | readCapability | updateCapability | deleteCapability | listCapability,
	}
	v.addPolicy(t, "pki", pc)

	// Generate a root CA
	caPath := path.Join(mountPath, "root/generate/internal")
	caOptions := map[string]any{
		"common_name": t.Name(),
		"ttl":         maxTTL.String(),
	}
	s, err := vc.Logical().Write(caPath, caOptions)
	require.NoError(err)
	require.NotEmpty(s)

	// Create default role
	rolePath := path.Join(mountPath, "roles", opts.roleName)
	roleOptions := map[string]any{
		"allow_any_name": true,
		"ttl":            defaultTTL.String(),
	}
	_, err = vc.Logical().Write(rolePath, roleOptions)
	require.NoError(err)

	return s
}

// AddKVPolicy adds a Vault policy named 'secret' to v and adds it to the
// standard set of polices attached to tokens created with v.CreateToken.
// The policy is defined as:
//
//	path "secret/*" {
//	  capabilities = ["create", "read", "update", "delete", "list"]
//	}
//
// All options are ignored.
func (v *TestVaultServer) AddKVPolicy(t testing.TB, _ ...TestOption) {
	t.Helper()

	pc := pathCapabilities{
		"secret/data/*": createCapability | readCapability | updateCapability | deleteCapability | listCapability,
	}
	v.addPolicy(t, "secret", pc)
}

// CreateKVSecret calls the /secret/data/:p endpoint with the provided
// data. Please note for KV-v2 the provided data needs to be in JSON format similar to:
// `{"data": {"key": "value", "key2": "value2"}}`
// See
// https://www.vaultproject.io/api-docs/secret/kv/kv-v2#create-update-secret
func (v *TestVaultServer) CreateKVSecret(t testing.TB, p string, data []byte) *vault.Secret {
	t.Helper()
	ctx := context.Background()
	require := require.New(t)

	vc := v.client(t)
	cred, err := vc.post(ctx, path.Join("secret", "data", p), data)
	require.NoError(err)
	return cred
}

// TestVaultServer is a vault server running in a docker container suitable
// for testing.
type TestVaultServer struct {
	RootToken string
	Addr      string

	CaCert        []byte
	ServerCert    []byte
	ClientCert    []byte
	ClientKey     []byte
	TlsServerName string
	TlsSkipVerify bool

	serverCertBundle *testCertBundle
	clientCertBundle *testCertBundle

	// Use any here instead of *dockertest.[Pool|Network|Resource] to avoid
	// problems with dockertest not building for some netbsd architectures.
	pool              any
	network           any
	vaultContainer    any
	ldapContainer     any
	postgresContainer any

	stopped  atomic.Bool
	Shutdown func(t *testing.T)
}

// NewTestVaultServer creates and returns a TestVaultServer. Some Vault
// secret engines require the Vault server be created with a docker
// network. Check the Mount method for the Vault secret engine to see if a
// docker network is required.
//
// WithTestVaultTLS and WithDockerNetwork are the only valid options.
// Setting the WithDockerNetwork option can significantly increase the
// amount of time required for a test to run.
func NewTestVaultServer(t testing.TB, opt ...TestOption) *TestVaultServer {
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
//	path "mountPath/*" {
//	  capabilities = ["create", "read", "update", "delete", "list"]
//	}
//
// MountDatabase returns a TestDatabase for testing credentials from the
// mount.
func (v *TestVaultServer) MountDatabase(t testing.TB, opt ...TestOption) *TestDatabase {
	t.Helper()
	return mountDatabase(t, v, opt...)
}

// TestDatabaseURL is a connection string with place holders for username
// and password to the database started by MountDatabase.
type TestDatabaseURL string

// Encode encodes the username and password credentials from s into u.
func (u TestDatabaseURL) Encode(t testing.TB, s *vault.Secret) string {
	t.Helper()
	require := require.New(t)
	require.NotNil(s, "vault.Secret")
	username, ok := s.Data["username"].(string)
	require.True(ok, "username")
	password, ok := s.Data["password"].(string)
	require.True(ok, "password")
	return fmt.Sprintf(string(u), username, password)
}

// TestDatabase is returned from MountDatabase and can be used to test
// database credentials returned by Vault for that mount.
type TestDatabase struct {
	URL TestDatabaseURL
}

// ValidateCredential tests the credentials in s against d. An error is
// returned if the credentials are not valid.
func (d *TestDatabase) ValidateCredential(t testing.TB, s *vault.Secret) error {
	t.Helper()
	require := require.New(t)
	require.NotNil(s)
	dburl := d.URL.Encode(t, s)
	db, err := common.SqlOpen("postgres", dburl)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		return err
	}
	return nil
}

// TestLdapServer is returned from MountLdapServer and contains information
// about how an LDAP server was setup. It is primarily used to test
// Boundary <> Vault <> LDAP Server interactions.
type TestLdapServer struct {
	BindDomain string
	BindPass   string
	BindDn     string
	Url        string
}

// MountLdapServer creates an LDAP server as a Docker container, within a
// running Vault's Docker network. Additionally, it mounts and configures the
// LDAP secrets engine in the passed in Vault instance.
//
// Supported options:
//   - WithBindPass. Controls the LDAP server's admin password. Defaults to
//     "admin".
//   - WithLdapRootDomain. Controls the LDAP server's root domain. Defaults to
//     "example.org".
//
// Some roles are added to the LDAP server as well as configured within Vault:
//   - scientists: A group of unique members: cn=scientists,dc=example,dc=org
//   - einstein: A user belonging to the scientists group: cn=einstein,dc=example,dc=org
//   - newton: Another user beloging to the scientists group: cn=newton,dc=example,dc=org
//
// Note that the domain components (dc) will change accordingly if WithDomain is
// passed in.
//
// Dynamic roles are also setup using LDIF templates. These roles trigger Vault
// to create users on-demand and manage their lifecycle. All dynamic users are
// added to the "scientists" group.
func MountLdapServer(t testing.TB, v *TestVaultServer, opt ...TestOption) *TestLdapServer {
	t.Helper()
	return mountLdapServer(t, v, opt...)
}
