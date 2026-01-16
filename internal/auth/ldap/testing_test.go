// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ldap

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_testAuthMethod(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	testWrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, testWrapper)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, testWrapper))
	databaseWrapper, err := testKms.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(err)

	testCtx := context.Background()
	c1, c1Pem := TestGenerateCA(t, "localhost")
	c2, c2Pem := TestGenerateCA(t, "127.0.0.1")
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(err)
	derPrivKey, err := x509.MarshalPKCS8PrivateKey(privKey)
	require.NoError(err)

	am := TestAuthMethod(
		t, conn, databaseWrapper,
		org.PublicId,
		[]string{"ldaps://d1.alice.com", "ldap://d2.alice.com"},
		WithName(testCtx, "test-name"),
		WithDescription(testCtx, "test-desc"),
		WithStartTLS(testCtx),
		WithInsecureTLS(testCtx),
		WithDiscoverDn(testCtx),
		WithAnonGroupSearch(testCtx),
		WithUpnDomain(testCtx, "alice.com"),
		WithCertificates(testCtx, c1, c2),
		WithUserDn(testCtx, "user-dn"),
		WithUserAttr(testCtx, "user-attr"),
		WithUserFilter(testCtx, "user-filter"),
		WithGroupDn(testCtx, "group-dn"),
		WithGroupAttr(testCtx, "group-attr"),
		WithGroupFilter(testCtx, "group-filter"),
		WithClientCertificate(testCtx, derPrivKey, c2), // not a client cert, but good enough for the test.
		WithBindCredential(testCtx, "bind-dn", "bind-password"),
	)

	rw := db.New(conn)
	found := AllocAuthMethod()
	found.PublicId = am.PublicId
	rw.LookupById(testCtx, &found)
	assert.Equal(am.PublicId, found.PublicId)
	assert.Equal(found.ScopeId, org.PublicId)
	assert.Equal(found.Name, "test-name")
	assert.Equal(found.Description, "test-desc")
	assert.Equal(found.OperationalState, InactiveState.String())
	assert.Equal(found.Version, uint32(1))
	assert.True(found.StartTls)
	assert.True(found.InsecureTls)
	assert.True(found.DiscoverDn)
	assert.True(found.AnonGroupSearch)
	assert.Equal("alice.com", found.UpnDomain)

	foundUrls := []*Url{}
	err = rw.SearchWhere(testCtx, &foundUrls, "ldap_method_id = ?", []any{found.PublicId}, db.WithOrder("connection_priority asc"))
	require.NoError(err)
	assert.Equal("ldaps://d1.alice.com", foundUrls[0].GetServerUrl())
	assert.Equal(uint32(1), foundUrls[0].ConnectionPriority)
	assert.Equal("ldap://d2.alice.com", foundUrls[1].GetServerUrl())
	assert.Equal(uint32(2), foundUrls[1].ConnectionPriority)

	foundCerts := []*Certificate{}
	err = rw.SearchWhere(testCtx, &foundCerts, "ldap_method_id = ?", []any{found.PublicId}, db.WithOrder("create_time asc"))
	require.NoError(err)
	assert.Equal(c1Pem, foundCerts[0].GetCert())
	assert.Equal(c2Pem, foundCerts[1].GetCert())

	foundUserSearchConf := allocUserEntrySearchConf()
	err = rw.LookupWhere(testCtx, &foundUserSearchConf, "ldap_method_id = ?", []any{found.PublicId})
	require.NoError(err)
	assert.Equal("user-dn", foundUserSearchConf.GetUserDn())
	assert.Equal("user-attr", foundUserSearchConf.GetUserAttr())
	assert.Equal("user-filter", foundUserSearchConf.GetUserFilter())

	foundGroupSearchConf := allocGroupEntrySearchConf()
	err = rw.LookupWhere(testCtx, &foundGroupSearchConf, "ldap_method_id = ?", []any{found.PublicId})
	require.NoError(err)
	assert.Equal("group-dn", foundGroupSearchConf.GetGroupDn())
	assert.Equal("group-attr", foundGroupSearchConf.GetGroupAttr())
	assert.Equal("group-filter", foundGroupSearchConf.GetGroupFilter())

	foundClientCert := allocClientCertificate()
	err = rw.LookupWhere(testCtx, &foundClientCert, "ldap_method_id = ?", []any{found.PublicId})
	require.NoError(err)
	require.NoError(foundClientCert.decrypt(testCtx, databaseWrapper))
	assert.NotEmpty(foundClientCert.GetKeyId())
	assert.NotEmpty(foundClientCert.GetCertificate())
	assert.NotEmpty(foundClientCert.GetCertificateKey())
	assert.NotEmpty(foundClientCert.GetCertificateKeyHmac())

	foundBindCred := allocBindCredential()
	err = rw.LookupWhere(testCtx, &foundBindCred, "ldap_method_id = ?", []any{found.PublicId})
	require.NoError(err)
	require.NoError(foundBindCred.decrypt(testCtx, databaseWrapper))
	assert.NotEmpty(foundBindCred.GetKeyId())
	assert.NotEmpty(foundBindCred.GetDn())
	assert.NotEmpty(foundBindCred.GetPassword())
	assert.NotEmpty(foundBindCred.GetPasswordHmac())
}
