package ldap

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_getOpts(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	t.Run("WithName", func(t *testing.T) {
		assert := assert.New(t)
		opts, err := getOpts(WithName(testCtx, "test"))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		assert.NotEqual(opts, testOpts)
		testOpts.withName = "test"
		assert.Equal(opts, testOpts)
	})
	t.Run("WithDescription", func(t *testing.T) {
		assert := assert.New(t)
		opts, err := getOpts(WithDescription(testCtx, "test"))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		assert.NotEqual(opts, testOpts)
		testOpts.withDescription = "test"
		assert.Equal(opts, testOpts)
	})
	t.Run("WithStartTLS", func(t *testing.T) {
		assert := assert.New(t)
		opts, err := getOpts(WithStartTLS(testCtx))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		assert.NotEqual(opts, testOpts)
		testOpts.withStartTls = true
		assert.Equal(opts, testOpts)
	})
	t.Run("WithInsecureTLS", func(t *testing.T) {
		assert := assert.New(t)
		opts, err := getOpts(WithInsecureTLS(testCtx))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		assert.NotEqual(opts, testOpts)
		testOpts.withInsecureTls = true
		assert.Equal(opts, testOpts)
	})
	t.Run("WithDiscoverDn", func(t *testing.T) {
		assert := assert.New(t)
		opts, err := getOpts(WithDiscoverDn(testCtx))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		assert.NotEqual(opts, testOpts)
		testOpts.withDiscoverDn = true
		assert.Equal(opts, testOpts)
	})
	t.Run("WithAnonGroupSearch", func(t *testing.T) {
		assert := assert.New(t)
		opts, err := getOpts(WithAnonGroupSearch(testCtx))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		assert.NotEqual(opts, testOpts)
		testOpts.withAnonGroupSearch = true
		assert.Equal(opts, testOpts)
	})
	t.Run("WithUpnDomain", func(t *testing.T) {
		assert := assert.New(t)
		opts, err := getOpts(WithUpnDomain(testCtx, "domain.com"))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		assert.NotEqual(opts, testOpts)
		testOpts.withUpnDomain = "domain.com"
		assert.Equal(opts, testOpts)
	})
	t.Run("WitUserDn", func(t *testing.T) {
		assert := assert.New(t)
		opts, err := getOpts(WithUserDn(testCtx, "dn"))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		assert.NotEqual(opts, testOpts)
		testOpts.withUserDn = "dn"
		assert.Equal(opts, testOpts)
	})
	t.Run("WitUserAttr", func(t *testing.T) {
		assert := assert.New(t)
		opts, err := getOpts(WithUserAttr(testCtx, "attr"))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		assert.NotEqual(opts, testOpts)
		testOpts.withUserAttr = "attr"
		assert.Equal(opts, testOpts)
	})
	t.Run("WitUserFilter", func(t *testing.T) {
		assert := assert.New(t)
		opts, err := getOpts(WithUserFilter(testCtx, "filter"))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		assert.NotEqual(opts, testOpts)
		testOpts.withUserFilter = "filter"
		assert.Equal(opts, testOpts)
	})
	t.Run("WitGroupDn", func(t *testing.T) {
		assert := assert.New(t)
		opts, err := getOpts(WithGroupDn(testCtx, "dn"))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		assert.NotEqual(opts, testOpts)
		testOpts.withGroupDn = "dn"
		assert.Equal(opts, testOpts)
	})
	t.Run("WithGroupAttr", func(t *testing.T) {
		assert := assert.New(t)
		opts, err := getOpts(WithGroupAttr(testCtx, "attr"))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		assert.NotEqual(opts, testOpts)
		testOpts.withGroupAttr = "attr"
		assert.Equal(opts, testOpts)
	})
	t.Run("WithGroupFilter", func(t *testing.T) {
		assert := assert.New(t)
		opts, err := getOpts(WithGroupFilter(testCtx, "filter"))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		assert.NotEqual(opts, testOpts)
		testOpts.withGroupFilter = "filter"
		assert.Equal(opts, testOpts)
	})
	t.Run("WithBindCredential", func(t *testing.T) {
		assert := assert.New(t)
		opts, err := getOpts(WithBindCredential(testCtx, "dn", "password"))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		assert.NotEqual(opts, testOpts)
		testOpts.withBindDn = "dn"
		testOpts.withBindPassword = "password"
		assert.Equal(opts, testOpts)
	})
	t.Run("WithBindCredential-missing-dn", func(t *testing.T) {
		assert := assert.New(t)
		opts, err := getOpts(WithBindCredential(testCtx, "", "password"))
		require.Error(t, err)
		assert.Empty(opts.withBindDn)
		assert.Empty(opts.withBindPassword)
	})
	t.Run("WithBindCredential-missing-password", func(t *testing.T) {
		assert := assert.New(t)
		opts, err := getOpts(WithBindCredential(testCtx, "dn", ""))
		require.Error(t, err)
		assert.Empty(opts.withBindDn)
		assert.Empty(opts.withBindPassword)
	})
	t.Run("WithBindCredential-missing-dn-and-password", func(t *testing.T) {
		assert := assert.New(t)
		opts, err := getOpts(WithBindCredential(testCtx, "", ""))
		require.Error(t, err)
		assert.Empty(opts.withBindDn)
	})
	t.Run("WithCertificates", func(t *testing.T) {
		assert := assert.New(t)
		testCert, _ := testGenerateCA(t, "localhost")
		testCert2, _ := testGenerateCA(t, "127.0.0.1")

		opts, err := getOpts(WithCertificates(testCtx, testCert, testCert2))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		encodedCerts, err := EncodeCertificates(testCtx, testCert, testCert2)
		require.NoError(t, err)
		testOpts.withCertificates = encodedCerts
		assert.Equal(opts, testOpts)
	})
	t.Run("WithClientCertificate", func(t *testing.T) {
		assert := assert.New(t)
		testCert, testCertEncoded := testGenerateCA(t, "localhost")
		_, testPrivKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		derPrivKey, err := x509.MarshalPKCS8PrivateKey(testPrivKey)
		require.NoError(t, err)

		opts, err := getOpts(WithClientCertificate(testCtx, derPrivKey, testCert))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.withClientCertificate = testCertEncoded
		testOpts.withClientCertificateKey = derPrivKey
		assert.Equal(opts, testOpts)

		// missing privKey
		_, err = getOpts(WithClientCertificate(testCtx, nil, testCert))
		require.Error(t, err)
		assert.Contains(err.Error(), "missing private key")

		// missing cert
		_, err = getOpts(WithClientCertificate(testCtx, derPrivKey, nil))
		require.Error(t, err)
		assert.Contains(err.Error(), "missing certificate")

		// bad privKey
		_, err = getOpts(WithClientCertificate(testCtx, []byte("not-a-kay"), testCert))
		require.Error(t, err)
		assert.Contains(err.Error(), "asn1: structure error")
	})
	t.Run("WithLimit", func(t *testing.T) {
		opts, err := getOpts(WithLimit(5))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.withLimit = 5
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithUnauthenticatedUser", func(t *testing.T) {
		assert := assert.New(t)
		opts, err := getOpts(WithUnauthenticatedUser(true))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.withUnauthenticatedUser = true
		assert.Equal(opts, testOpts)
	})
	t.Run("WithOrderByCreateTime", func(t *testing.T) {
		assert := assert.New(t)
		opts, err := getOpts(WithOrderByCreateTime(true))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.withOrderByCreateTime = true
		testOpts.ascending = true
		assert.Equal(opts, testOpts)
	})
	t.Run("WithOperationalState", func(t *testing.T) {
		assert := assert.New(t)
		opts, err := getOpts(WithOperationalState(ActivePublicState))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.withOperationalState = ActivePublicState
		assert.Equal(opts, testOpts)
	})
}
