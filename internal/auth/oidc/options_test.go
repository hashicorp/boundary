package oidc

import (
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test_GetOpts provides unit tests for GetOpts and all the options
func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("WithName", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithName("test"))
		testOpts := getDefaultOptions()
		testOpts.withName = "test"
		assert.Equal(opts, testOpts)
	})
	t.Run("WithDescription", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithDescription("test desc"))
		testOpts := getDefaultOptions()
		testOpts.withDescription = "test desc"
		assert.Equal(opts, testOpts)
	})
	t.Run("WithLimit", func(t *testing.T) {
		assert := assert.New(t)
		// test default of 0
		opts := getOpts()
		testOpts := getDefaultOptions()
		testOpts.withLimit = 0
		assert.Equal(opts, testOpts)

		opts = getOpts(WithLimit(-1))
		testOpts = getDefaultOptions()
		testOpts.withLimit = -1
		assert.Equal(opts, testOpts)

		opts = getOpts(WithLimit(1))
		testOpts = getDefaultOptions()
		testOpts.withLimit = 1
		assert.Equal(opts, testOpts)
	})
	t.Run("WithMaxAge", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithMaxAge(1000))
		testOpts := getDefaultOptions()
		testOpts.withMaxAge = 1000
		assert.Equal(opts, testOpts)
	})
	t.Run("WithCallbackUrls", func(t *testing.T) {
		assert := assert.New(t)
		u := TestConvertToUrls(t, "https://alice.com?callback", "http://localhost:8080?callback")
		opts := getOpts(WithCallbackUrls(u...))
		testOpts := getDefaultOptions()
		testOpts.withCallbackUrls = u
		assert.Equal(opts, testOpts)
	})
	t.Run("WithCertificates", func(t *testing.T) {
		assert := assert.New(t)
		testCert, _ := testGenerateCA(t, "localhost")
		testCert2, _ := testGenerateCA(t, "127.0.0.1")

		opts := getOpts(WithCertificates(testCert, testCert2))
		testOpts := getDefaultOptions()
		testOpts.withCertificates = []*x509.Certificate{testCert, testCert2}
		assert.Equal(opts, testOpts)
	})
	t.Run("WithAudClaims", func(t *testing.T) {
		assert := assert.New(t)
		aud := []string{"alice.com", "eve.com", "bob.com"}
		opts := getOpts(WithAudClaims(aud...))
		testOpts := getDefaultOptions()
		testOpts.withAudClaims = aud
		assert.Equal(opts, testOpts)
	})
	t.Run("WithSigningAlgs", func(t *testing.T) {
		assert := assert.New(t)
		algs := []Alg{RS256, RS384, RS512}
		opts := getOpts(WithSigningAlgs(algs...))
		testOpts := getDefaultOptions()
		testOpts.withSigningAlgs = algs
		assert.Equal(opts, testOpts)
	})
	t.Run("WithEmail", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithEmail("bob@alice.com"))
		testOpts := getDefaultOptions()
		testOpts.withEmail = "bob@alice.com"
		assert.Equal(opts, testOpts)
	})
	t.Run("WithFullName", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithFullName("Bob Eve Alice"))
		testOpts := getDefaultOptions()
		testOpts.withFullName = "Bob Eve Alice"
		assert.Equal(opts, testOpts)
	})
	t.Run("WithOrder", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithOrder("public_id asc"))
		testOpts := getDefaultOptions()
		testOpts.withOrderClause = "public_id asc"
		assert.Equal(opts, testOpts)
	})
	t.Run("WithUnauthenticatedUser", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithUnauthenticatedUser(true))
		testOpts := getDefaultOptions()
		testOpts.withUnauthenticatedUser = true
		assert.Equal(opts, testOpts)
	})
	t.Run("WithForce", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithForce())
		testOpts := getDefaultOptions()
		testOpts.withForce = true
		assert.Equal(opts, testOpts)
	})
	t.Run("WithDryRun", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithDryRun())
		testOpts := getDefaultOptions()
		testOpts.withDryRun = true
		assert.Equal(opts, testOpts)
	})
	t.Run("WithAuthMethod", func(t *testing.T) {
		assert := assert.New(t)
		am := AllocAuthMethod()
		am.PublicId = "alice's-auth-method"
		opts := getOpts(WithAuthMethod(&am))
		testOpts := getDefaultOptions()
		testOpts.withAuthMethod = &am
		assert.Equal(opts, testOpts)
	})
	t.Run("WithPublicId", func(t *testing.T) {
		assert := assert.New(t)
		id := "alice's-auth-method"
		opts := getOpts(WithPublicId(id))
		testOpts := getDefaultOptions()
		testOpts.withPublicId = id
		assert.Equal(opts, testOpts)
	})
	t.Run("WithRoundtripPayload", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithRoundtripPayload("payload"))
		testOpts := getDefaultOptions()
		testOpts.withRoundtripPayload = "payload"
		assert.Equal(opts, testOpts)
	})
	t.Run("WithKeyId", func(t *testing.T) {
		assert := assert.New(t)
		opts := getOpts(WithKeyId("specific_id"))
		testOpts := getDefaultOptions()
		testOpts.withKeyId = "specific_id"
		assert.Equal(opts, testOpts)
	})
}
