// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ldap

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeItem struct {
	pagination.Item
	publicId   string
	createTime time.Time
	updateTime time.Time
}

func (p *fakeItem) GetPublicId() string {
	return p.publicId
}

func (p *fakeItem) GetCreateTime() *timestamp.Timestamp {
	return timestamp.New(p.createTime)
}

func (p *fakeItem) GetUpdateTime() *timestamp.Timestamp {
	return timestamp.New(p.updateTime)
}

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
	t.Run("WithUrls", func(t *testing.T) {
		assert := assert.New(t)
		opts, err := getOpts(WithUrls(testCtx, TestConvertToUrls(t, "ldaps://ldap1")...))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		assert.NotEqual(opts, testOpts)
		testOpts.withUrls = []string{"ldaps://ldap1"}
		assert.Equal(opts, testOpts)
	})
	t.Run("WithAccountAttributeMap", func(t *testing.T) {
		assert := assert.New(t)
		opts, err := getOpts(WithAccountAttributeMap(testCtx, map[string]AccountToAttribute{
			"mail": ToEmailAttribute,
		}))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		assert.NotEqual(opts, testOpts)
		testOpts.withAccountAttributeMap = map[string]AccountToAttribute{
			"mail": ToEmailAttribute,
		}
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
	t.Run("WithEnableGroups", func(t *testing.T) {
		assert := assert.New(t)
		opts, err := getOpts(WithEnableGroups(testCtx))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		assert.NotEqual(opts, testOpts)
		testOpts.withEnableGroups = true
		assert.Equal(opts, testOpts)
	})
	t.Run("WithUseTokenGroups", func(t *testing.T) {
		assert := assert.New(t)
		opts, err := getOpts(WithUseTokenGroups(testCtx))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		assert.NotEqual(opts, testOpts)
		testOpts.withUseTokenGroups = true
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
	t.Run("WithBindCredential-only-password", func(t *testing.T) {
		assert := assert.New(t)
		opts, err := getOpts(WithBindCredential(testCtx, "", "password"))
		require.NoError(t, err)
		assert.Empty(opts.withBindDn)
		assert.NotEmpty(opts.withBindPassword)
	})
	t.Run("WithBindCredential-only-dn", func(t *testing.T) {
		assert := assert.New(t)
		opts, err := getOpts(WithBindCredential(testCtx, "dn", ""))
		require.NoError(t, err)
		assert.NotEmpty(opts.withBindDn)
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
		testCert, _ := TestGenerateCA(t, "localhost")
		testCert2, _ := TestGenerateCA(t, "127.0.0.1")

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
		testCert, testCertEncoded := TestGenerateCA(t, "localhost")
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
		opts, err := getOpts(WithLimit(testCtx, 5))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.withLimit = 5
		assert.Equal(t, opts, testOpts)
	})
	t.Run("WithUnauthenticatedUser", func(t *testing.T) {
		assert := assert.New(t)
		opts, err := getOpts(WithUnauthenticatedUser(testCtx, true))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.withUnauthenticatedUser = true
		assert.Equal(opts, testOpts)
	})
	t.Run("WithOrderByCreateTime", func(t *testing.T) {
		assert := assert.New(t)
		opts, err := getOpts(WithOrderByCreateTime(testCtx, true))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.withOrderByCreateTime = true
		testOpts.ascending = true
		assert.Equal(opts, testOpts)
	})
	t.Run("WithOperationalState", func(t *testing.T) {
		assert := assert.New(t)
		opts, err := getOpts(WithOperationalState(testCtx, ActivePublicState))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		testOpts.withOperationalState = ActivePublicState
		assert.Equal(opts, testOpts)
	})
	t.Run("WithDn", func(t *testing.T) {
		assert := assert.New(t)
		opts, err := getOpts(WithDn(testCtx, "test"))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		assert.NotEqual(opts, testOpts)
		testOpts.withDn = "test"
		assert.Equal(opts, testOpts)
	})
	t.Run("WithFullName", func(t *testing.T) {
		assert := assert.New(t)
		opts, err := getOpts(WithFullName(testCtx, "test"))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		assert.NotEqual(opts, testOpts)
		testOpts.withFullName = "test"
		assert.Equal(opts, testOpts)
	})
	t.Run("WithEmail", func(t *testing.T) {
		assert := assert.New(t)
		opts, err := getOpts(WithEmail(testCtx, "test"))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		assert.NotEqual(opts, testOpts)
		testOpts.withEmail = "test"
		assert.Equal(opts, testOpts)
	})
	t.Run("WithMemberOfGroups", func(t *testing.T) {
		assert := assert.New(t)
		opts, err := getOpts(WithMemberOfGroups(testCtx, "test"))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		assert.NotEqual(opts, testOpts)
		testOpts.withMemberOfGroups = "[\"test\"]"
		assert.Equal(opts, testOpts)
	})
	t.Run("WithPublicId", func(t *testing.T) {
		assert := assert.New(t)
		opts, err := getOpts(WithPublicId(testCtx, "test"))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		assert.NotEqual(opts, testOpts)
		testOpts.withPublicId = "test"
		assert.Equal(opts, testOpts)
	})
	t.Run("WithMaximumPageSize", func(t *testing.T) {
		assert := assert.New(t)
		opts, err := getOpts(WithMaximumPageSize(testCtx, 10))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		assert.NotEqual(opts, testOpts)
		testOpts.withMaximumPageSize = 10
		assert.Equal(opts, testOpts)
	})
	t.Run("WithDerefAliases", func(t *testing.T) {
		assert := assert.New(t)
		opts, err := getOpts(WithDerefAliases(testCtx, DerefAlways))
		require.NoError(t, err)
		testOpts := getDefaultOptions()
		assert.NotEqual(opts, testOpts)
		testOpts.withDerefAliases = DerefAlways
		assert.Equal(opts, testOpts)
	})
	t.Run("WithDerefAliases-invalid", func(t *testing.T) {
		assert := assert.New(t)
		_, err := getOpts(WithDerefAliases(testCtx, "Invalid"))
		require.Error(t, err)
		assert.ErrorContains(err, `"Invalid" is not a valid ldap dereference alias type`)
		assert.Truef(errors.Match(errors.T(errors.InvalidParameter), err), "want err code: %q got: %q", errors.InvalidParameter, err)
	})
	t.Run("WithStartPageAfterItem", func(t *testing.T) {
		t.Run("nil item", func(t *testing.T) {
			_, err := getOpts(WithStartPageAfterItem(context.Background(), nil))
			require.Error(t, err)
		})
		assert := assert.New(t)
		updateTime := time.Now()
		createTime := time.Now()
		opts, err := getOpts(WithStartPageAfterItem(context.Background(), &fakeItem{nil, "s_1", createTime, updateTime}))
		require.NoError(t, err)
		assert.Equal(opts.withStartPageAfterItem.GetPublicId(), "s_1")
		assert.Equal(opts.withStartPageAfterItem.GetUpdateTime(), timestamp.New(updateTime))
		assert.Equal(opts.withStartPageAfterItem.GetCreateTime(), timestamp.New(createTime))
	})
}
