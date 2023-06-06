// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("WithName", func(t *testing.T) {
		opts := getOpts(WithName("test"))
		testOpts := getDefaultOptions()
		testOpts.withName = "test"
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithDescription", func(t *testing.T) {
		opts := getOpts(WithDescription("test desc"))
		testOpts := getDefaultOptions()
		testOpts.withDescription = "test desc"
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithWorkerFilter", func(t *testing.T) {
		opts := getOpts(WithWorkerFilter("test filter"))
		testOpts := getDefaultOptions()
		testOpts.withWorkerFilter = "test filter"
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithLimit", func(t *testing.T) {
		opts := getOpts(WithLimit(5))
		testOpts := getDefaultOptions()
		testOpts.withLimit = 5
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithCACert", func(t *testing.T) {
		opts := getOpts(WithCACert([]byte("test cert")))
		testOpts := getDefaultOptions()
		testOpts.withCACert = []byte("test cert")
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithNamespace", func(t *testing.T) {
		opts := getOpts(WithNamespace("namespace"))
		testOpts := getDefaultOptions()
		testOpts.withNamespace = "namespace"
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithTlsServerName", func(t *testing.T) {
		opts := getOpts(WithTlsServerName("server"))
		testOpts := getDefaultOptions()
		testOpts.withTlsServerName = "server"
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithTlsSkipVerify", func(t *testing.T) {
		opts := getOpts(WithTlsSkipVerify(true))
		testOpts := getDefaultOptions()
		testOpts.withTlsSkipVerify = true
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithClientCert", func(t *testing.T) {
		testOpts := getDefaultOptions()
		assert.Nil(t, testOpts.withClientCert)
		inCert := testClientCert(t, testCaCert(t))
		cert := inCert.Cert.Cert
		key := inCert.Cert.Key
		clientCert, err := NewClientCertificate(context.Background(), cert, key)
		assert.NoError(t, err)
		assert.NotNil(t, clientCert)
		opts := getOpts(WithClientCert(clientCert))
		require.NotNil(t, opts.withClientCert)
		assert.Equal(t, cert, opts.withClientCert.Certificate)
		assert.Equal(t, key, opts.withClientCert.CertificateKey)
	})
	t.Run("WithMethod_Get", func(t *testing.T) {
		opts := getOpts(WithMethod(MethodGet))
		testOpts := getDefaultOptions()
		testOpts.withMethod = MethodGet
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithMethod_Post", func(t *testing.T) {
		opts := getOpts(WithMethod(MethodPost))
		testOpts := getDefaultOptions()
		testOpts.withMethod = MethodPost
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithRequestBody", func(t *testing.T) {
		opts := getOpts(WithRequestBody([]byte("body")))
		testOpts := getDefaultOptions()
		testOpts.withRequestBody = []byte("body")
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithCredentialType", func(t *testing.T) {
		opts := getOpts(WithCredentialType(credential.UsernamePasswordType))
		testOpts := getDefaultOptions()
		testOpts.withCredentialType = credential.UsernamePasswordType
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithOverrideUsernameAttribute", func(t *testing.T) {
		opts := getOpts(WithOverrideUsernameAttribute("test"))
		testOpts := getDefaultOptions()
		testOpts.withOverrideUsernameAttribute = "test"
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithOverridePasswordAttribute", func(t *testing.T) {
		opts := getOpts(WithOverridePasswordAttribute("test"))
		testOpts := getDefaultOptions()
		testOpts.withOverridePasswordAttribute = "test"
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithOverridePrivateKeyAttribute", func(t *testing.T) {
		opts := getOpts(WithOverridePrivateKeyAttribute("test"))
		testOpts := getDefaultOptions()
		testOpts.withOverridePrivateKeyAttribute = "test"
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithOverridePrivateKeyPassphraseAttribute", func(t *testing.T) {
		opts := getOpts(WithOverridePrivateKeyPassphraseAttribute("test"))
		testOpts := getDefaultOptions()
		assert.NotEqual(t, opts, testOpts)
		testOpts.withOverridePrivateKeyPassphraseAttribute = "test"
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithMappingOverride", func(t *testing.T) {
		opts := getOpts(WithMappingOverride(unknownMapper(1)))
		testOpts := getDefaultOptions()
		testOpts.withMappingOverride = unknownMapper(1)
		assert.Equal(t, opts, testOpts)
	})
}
