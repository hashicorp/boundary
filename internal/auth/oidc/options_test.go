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
}
