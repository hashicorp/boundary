// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ldap

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestRepository_UpdateAuthMethod(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	testConn, _ := db.TestSetup(t, "postgres")
	testWrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, testConn, testWrapper)
	testRw := db.New(testConn)
	testRepo, err := NewRepository(testCtx, testRw, testRw, testKms)
	require.NoError(t, err)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, testConn, testWrapper))
	databaseWrapper, err := testKms.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	testCert, testCertEncoded := TestGenerateCA(t, "localhost")
	_, testPrivKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	derPrivKey, err := x509.MarshalPKCS8PrivateKey(testPrivKey)
	require.NoError(t, err)

	_, testCertEncoded2 := TestGenerateCA(t, "localhost")
	_, testPrivKey2, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	derPrivKey2, err := x509.MarshalPKCS8PrivateKey(testPrivKey2)
	require.NoError(t, err)

	tests := []struct {
		name              string
		ctx               context.Context
		repo              *Repository
		setup             func() *AuthMethod
		updateWith        func(orig *AuthMethod) *AuthMethod
		fieldMasks        []string
		version           uint32
		opt               []Option
		want              func(orig, updateWith *AuthMethod) *AuthMethod
		wantErrMatch      *errors.Template
		wantErrContains   string
		wantNoRowsUpdated bool
	}{
		{
			name: "update-everything",
			ctx:  testCtx,
			repo: testRepo,
			setup: func() *AuthMethod {
				return TestAuthMethod(t,
					testConn, databaseWrapper,
					org.PublicId,
					[]string{"ldaps://ldap1", "ldap://ldap2"},
					WithName(testCtx, "update-everything-test-name"),
					WithDescription(testCtx, "update-everything-test-description"),
					WithUpnDomain(testCtx, "orig.alice.com"),
					WithUserDn(testCtx, "orig-user-dn"),
					WithUserAttr(testCtx, "orig-user-attr"),
					WithUserFilter(testCtx, "orig-user-filter"),
					WithGroupDn(testCtx, "orig-group-dn"),
					WithGroupAttr(testCtx, "orig-group-attr"),
					WithGroupFilter(testCtx, "orig-group-filter"),
					WithBindCredential(testCtx, "orig-bind-dn", "orig-bind-password"),
					WithCertificates(testCtx, testCert),
					WithClientCertificate(testCtx, derPrivKey, testCert), // not a client cert but good enough for this test.
					WithAccountAttributeMap(testCtx, map[string]AccountToAttribute{
						"displayName": ToFullNameAttribute,
						"mail":        ToEmailAttribute,
					}),
					WithDerefAliases(testCtx, DerefAlways),
					WithMaximumPageSize(testCtx, 10),
				)
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				am := AllocAuthMethod()
				am.PublicId = orig.PublicId
				am.Urls = []string{"ldaps://ldap1.alice.com", "ldaps://ldap2.alice.com"}
				am.OperationalState = string(ActivePublicState)
				am.Name = "update-everything-updated-name"
				am.Description = "update-everything-updated-description"
				am.StartTls = true
				am.InsecureTls = true
				am.DiscoverDn = true
				am.AnonGroupSearch = true
				am.EnableGroups = true
				am.UseTokenGroups = true
				am.UpnDomain = "alice.com"
				am.UserDn = "user-dn"
				am.UserAttr = "user-attr"
				am.UserFilter = "user-filter"
				am.GroupDn = "group-dn"
				am.GroupAttr = "group-attr"
				am.GroupFilter = "group-filter"
				am.BindDn = "bind-dn"
				am.BindPassword = "bind-password"
				am.Certificates = []string{testCertEncoded2}
				am.ClientCertificate = testCertEncoded2
				am.ClientCertificateKey = derPrivKey2
				am.AccountAttributeMaps = []string{
					fmt.Sprintf("%s=%s", "cn", ToFullNameAttribute),
				}
				am.DereferenceAliases = string(NeverDerefAliases)
				am.MaximumPageSize = 100
				return &am
			},
			fieldMasks: []string{
				OperationalStateField,
				NameField,
				DescriptionField,
				UrlsField,
				StartTlsField,
				InsecureTlsField,
				DiscoverDnField,
				AnonGroupSearchField,
				UpnDomainField,
				UserDnField,
				UserAttrField,
				UserFilterField,
				EnableGroupsField,
				UseTokenGroupsField,
				GroupDnField,
				GroupAttrField,
				GroupFilterField,
				BindDnField,
				BindPasswordField,
				CertificatesField,
				ClientCertificateField,
				ClientCertificateKeyField,
				AccountAttributeMapsField,
				DerefAliasesField,
				MaximumPageSizeField,
			},
			version: 1,
			want: func(orig, updateWith *AuthMethod) *AuthMethod {
				am := orig.clone()
				am.OperationalState = string(ActivePublicState)
				am.Name = updateWith.Name
				am.Description = updateWith.Description
				am.Urls = updateWith.Urls
				am.StartTls = updateWith.StartTls
				am.InsecureTls = updateWith.InsecureTls
				am.DiscoverDn = updateWith.DiscoverDn
				am.AnonGroupSearch = updateWith.AnonGroupSearch
				am.UpnDomain = updateWith.UpnDomain
				am.UserDn = updateWith.UserDn
				am.UserAttr = updateWith.UserAttr
				am.UserFilter = updateWith.UserFilter
				am.EnableGroups = updateWith.EnableGroups
				am.UseTokenGroups = updateWith.UseTokenGroups
				am.GroupDn = updateWith.GroupDn
				am.GroupAttr = updateWith.GroupAttr
				am.GroupFilter = updateWith.GroupFilter
				am.BindDn = updateWith.BindDn
				am.BindPassword = updateWith.BindPassword
				am.BindPasswordHmac = updateWith.BindPasswordHmac
				am.Certificates = updateWith.Certificates
				am.ClientCertificateKey = updateWith.ClientCertificateKey
				am.ClientCertificate = updateWith.ClientCertificate
				am.ClientCertificateKeyHmac = updateWith.ClientCertificateKeyHmac
				am.AccountAttributeMaps = updateWith.AccountAttributeMaps
				am.DereferenceAliases = string(NeverDerefAliases)
				am.MaximumPageSize = 100
				return am
			},
		},
		{
			name: "update-nothing",
			ctx:  testCtx,
			repo: testRepo,
			setup: func() *AuthMethod {
				return TestAuthMethod(t,
					testConn, databaseWrapper,
					org.PublicId,
					[]string{"ldaps://ldap1", "ldap://ldap2"},
					WithName(testCtx, "update-nothing-test-name"),
					WithDescription(testCtx, "update-nothing-test-description"),
					WithUpnDomain(testCtx, "orig.alice.com"),
					WithUserDn(testCtx, "orig-user-dn"),
					WithUserAttr(testCtx, "orig-user-attr"),
					WithUserFilter(testCtx, "orig-user-filter"),
					WithGroupDn(testCtx, "orig-group-dn"),
					WithGroupAttr(testCtx, "orig-group-attr"),
					WithGroupFilter(testCtx, "orig-group-filter"),
					WithBindCredential(testCtx, "orig-bind-dn", "orig-bind-password"),
					WithCertificates(testCtx, testCert),
					WithClientCertificate(testCtx, derPrivKey, testCert), // not a client cert but good enough for this test.
					WithAccountAttributeMap(testCtx, map[string]AccountToAttribute{
						"mail": ToEmailAttribute,
						"cn":   ToFullNameAttribute,
					}),
				)
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				return orig.clone()
			},
			fieldMasks: []string{
				NameField,
				DescriptionField,
				UrlsField,
				StartTlsField,
				InsecureTlsField,
				DiscoverDnField,
				AnonGroupSearchField,
				UpnDomainField,
				UserDnField,
				UserAttrField,
				UserFilterField,
				EnableGroupsField,
				UseTokenGroupsField,
				GroupDnField,
				GroupAttrField,
				GroupFilterField,
				BindDnField,
				BindPasswordField,
				CertificatesField,
				ClientCertificateField,
				AccountAttributeMapsField,
			},
			version: 1,
			want: func(orig, updateWith *AuthMethod) *AuthMethod {
				return orig.clone()
			},
		},
		{
			name: "only-update-attributes",
			ctx:  testCtx,
			repo: testRepo,
			setup: func() *AuthMethod {
				return TestAuthMethod(t,
					testConn, databaseWrapper,
					org.PublicId,
					[]string{"ldaps://ldap1", "ldap://ldap2"},
					WithName(testCtx, "only-update-attributes-test-name"),
					WithDescription(testCtx, "only-update-attributes-test-description"),
					WithUpnDomain(testCtx, "orig.alice.com"),
					WithUserDn(testCtx, "orig-user-dn"),
					WithUserAttr(testCtx, "orig-user-attr"),
					WithUserFilter(testCtx, "orig-user-filter"),
					WithGroupDn(testCtx, "orig-group-dn"),
					WithGroupAttr(testCtx, "orig-group-attr"),
					WithGroupFilter(testCtx, "orig-group-filter"),
					WithBindCredential(testCtx, "orig-bind-dn", "orig-bind-password"),
					WithCertificates(testCtx, testCert),
					WithClientCertificate(testCtx, derPrivKey, testCert), // not a client cert but good enough for this test.
				)
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				am := AllocAuthMethod()
				am.PublicId = orig.PublicId
				am.OperationalState = string(ActivePublicState)
				am.Name = "only-update-attributes-updated-name"
				am.Description = "only-update-attributes-updated-description"
				am.StartTls = true
				am.InsecureTls = true
				am.DiscoverDn = true
				am.AnonGroupSearch = true
				am.EnableGroups = true
				am.UseTokenGroups = true
				am.UpnDomain = "alice.com"
				return &am
			},
			fieldMasks: []string{
				NameField,
				DescriptionField,
				StartTlsField,
				InsecureTlsField,
				DiscoverDnField,
				AnonGroupSearchField,
				EnableGroupsField,
				UseTokenGroupsField,
				UpnDomainField,
			},
			version: 1,
			want: func(orig, updateWith *AuthMethod) *AuthMethod {
				am := orig.clone()
				am.Name = updateWith.Name
				am.Description = updateWith.Description
				am.StartTls = updateWith.StartTls
				am.InsecureTls = updateWith.InsecureTls
				am.DiscoverDn = updateWith.DiscoverDn
				am.AnonGroupSearch = updateWith.AnonGroupSearch
				am.UpnDomain = updateWith.UpnDomain
				am.EnableGroups = updateWith.EnableGroups
				am.UseTokenGroups = updateWith.UseTokenGroups
				return am
			},
		},
		{
			name: "all-attributes-set-to-null-or-empty",
			ctx:  testCtx,
			repo: testRepo,
			setup: func() *AuthMethod {
				return TestAuthMethod(t,
					testConn, databaseWrapper,
					org.PublicId,
					[]string{"ldaps://ldap1", "ldap://ldap2"},
					WithName(testCtx, "all-attributes-set-to-null-or-empty-test-name"),
					WithDescription(testCtx, "all-attributes-set-to-null-or-empty-description"),
					WithUpnDomain(testCtx, "orig.alice.com"),
					WithUserDn(testCtx, "orig-user-dn"),
					WithUserAttr(testCtx, "orig-user-attr"),
					WithUserFilter(testCtx, "orig-user-filter"),
					WithGroupDn(testCtx, "orig-group-dn"),
					WithGroupAttr(testCtx, "orig-group-attr"),
					WithGroupFilter(testCtx, "orig-group-filter"),
					WithBindCredential(testCtx, "orig-bind-dn", "orig-bind-password"),
					WithCertificates(testCtx, testCert),
					WithClientCertificate(testCtx, derPrivKey, testCert), // not a client cert but good enough for this test.
					WithDerefAliases(testCtx, DerefAlways),
					WithMaximumPageSize(testCtx, 10),
				)
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				am := AllocAuthMethod()
				am.PublicId = orig.PublicId
				return &am
			},
			fieldMasks: []string{
				NameField,
				DescriptionField,
				StartTlsField,
				InsecureTlsField,
				DiscoverDnField,
				AnonGroupSearchField,
				UpnDomainField,
				EnableGroupsField,
				UseTokenGroupsField,
				DerefAliasesField,
				MaximumPageSizeField,
			},
			version: 1,
			want: func(orig, updateWith *AuthMethod) *AuthMethod {
				am := orig.clone()
				am.Name = updateWith.Name
				am.Description = updateWith.Description
				am.StartTls = updateWith.StartTls
				am.InsecureTls = updateWith.InsecureTls
				am.DiscoverDn = updateWith.DiscoverDn
				am.AnonGroupSearch = updateWith.AnonGroupSearch
				am.UpnDomain = updateWith.UpnDomain
				am.EnableGroups = updateWith.EnableGroups
				am.UseTokenGroups = updateWith.UseTokenGroups
				am.MaximumPageSize = updateWith.MaximumPageSize
				am.DereferenceAliases = updateWith.DereferenceAliases
				return am
			},
		},
		{
			name: "only-update-value-objects",
			ctx:  testCtx,
			repo: testRepo,
			setup: func() *AuthMethod {
				return TestAuthMethod(t,
					testConn, databaseWrapper,
					org.PublicId,
					[]string{"ldaps://ldap1", "ldap://ldap2"},
					WithName(testCtx, "only-update-value-objects-test-name"),
					WithDescription(testCtx, "orig-test-description"),
					WithUpnDomain(testCtx, "orig.alice.com"),
					WithUserDn(testCtx, "orig-user-dn"),
					WithUserAttr(testCtx, "orig-user-attr"),
					WithUserFilter(testCtx, "orig-user-filter"),
					WithGroupDn(testCtx, "orig-group-dn"),
					WithGroupAttr(testCtx, "orig-group-attr"),
					WithGroupFilter(testCtx, "orig-group-filter"),
					WithBindCredential(testCtx, "orig-bind-dn", "orig-bind-password"),
					WithCertificates(testCtx, testCert),
					WithClientCertificate(testCtx, derPrivKey, testCert), // not a client cert but good enough for this test.
					WithAccountAttributeMap(testCtx, map[string]AccountToAttribute{
						"mail": ToEmailAttribute,
						"cn":   ToFullNameAttribute,
					}),
					WithDerefAliases(testCtx, NeverDerefAliases),
				)
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				am := AllocAuthMethod()
				am.PublicId = orig.PublicId
				am.Urls = []string{"ldaps://ldap3", "ldaps://ldap4"}
				am.UserDn = "user-dn"
				am.UserAttr = "user-attr"
				am.UserFilter = "user-filter"
				am.GroupDn = "group-dn"
				am.GroupAttr = "group-attr"
				am.GroupFilter = "group-filter"
				am.BindDn = "bind-dn"
				am.BindPassword = "bind-password"
				am.Certificates = []string{testCertEncoded}
				am.ClientCertificate = testCertEncoded
				am.ClientCertificateKey = derPrivKey
				am.AccountAttributeMaps = []string{"cn=fullName"}
				am.DereferenceAliases = string(DerefAlways)
				return &am
			},
			fieldMasks: []string{
				UrlsField,
				UserDnField,
				UserAttrField,
				UserFilterField,
				GroupDnField,
				GroupAttrField,
				GroupFilterField,
				BindDnField,
				BindPasswordField,
				CertificatesField,
				ClientCertificateField,
				ClientCertificateKeyField,
				AccountAttributeMapsField,
				DerefAliasesField,
			},
			version: 1,
			want: func(orig, updateWith *AuthMethod) *AuthMethod {
				am := orig.clone()
				am.Urls = updateWith.Urls
				am.UserDn = updateWith.UserDn
				am.UserAttr = updateWith.UserAttr
				am.UserFilter = updateWith.UserFilter
				am.GroupDn = updateWith.GroupDn
				am.GroupAttr = updateWith.GroupAttr
				am.GroupFilter = updateWith.GroupFilter
				am.BindDn = updateWith.BindDn
				am.BindPassword = updateWith.BindPassword
				am.BindPasswordHmac = updateWith.BindPasswordHmac
				am.ClientCertificateKey = updateWith.ClientCertificateKey
				am.ClientCertificate = updateWith.ClientCertificate
				am.ClientCertificateKeyHmac = updateWith.ClientCertificateKeyHmac
				am.AccountAttributeMaps = updateWith.AccountAttributeMaps
				am.DereferenceAliases = updateWith.DereferenceAliases
				return am
			},
		},
		{
			name: "remove-value-objects",
			ctx:  testCtx,
			repo: testRepo,
			setup: func() *AuthMethod {
				return TestAuthMethod(t,
					testConn, databaseWrapper,
					org.PublicId,
					[]string{"ldaps://ldap1", "ldap://ldap2"},
					WithUserDn(testCtx, "orig-user-dn"),
					WithUserAttr(testCtx, "orig-user-attr"),
					WithUserFilter(testCtx, "orig-user-filter"),
					WithGroupDn(testCtx, "orig-group-dn"),
					WithGroupAttr(testCtx, "orig-group-attr"),
					WithGroupFilter(testCtx, "orig-group-filter"),
					WithBindCredential(testCtx, "orig-bind-dn", "orig-bind-password"),
					WithCertificates(testCtx, testCert),
					WithClientCertificate(testCtx, derPrivKey, testCert), // not a client cert but good enough for this test.
					WithAccountAttributeMap(testCtx, map[string]AccountToAttribute{
						"mail": ToEmailAttribute,
						"cn":   ToFullNameAttribute,
					}),
					WithDerefAliases(testCtx, DerefAlways),
				)
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				am := AllocAuthMethod()
				am.PublicId = orig.PublicId
				return &am
			},
			fieldMasks: []string{
				UserDnField,
				UserAttrField,
				UserFilterField,
				GroupDnField,
				GroupAttrField,
				GroupFilterField,
				BindDnField,
				BindPasswordField,
				CertificatesField,
				ClientCertificateField,
				ClientCertificateKeyField,
				AccountAttributeMapsField,
				DerefAliasesField,
			},
			version: 1,
			want: func(orig, updateWith *AuthMethod) *AuthMethod {
				am := orig.clone()
				am.Certificates = updateWith.Certificates
				am.UserDn = updateWith.UserDn
				am.UserAttr = updateWith.UserAttr
				am.UserFilter = updateWith.UserFilter
				am.GroupDn = updateWith.GroupDn
				am.GroupAttr = updateWith.GroupAttr
				am.GroupFilter = updateWith.GroupFilter
				am.BindDn = updateWith.BindDn
				am.BindPassword = updateWith.BindPassword
				am.BindPasswordHmac = updateWith.BindPasswordHmac
				am.ClientCertificateKey = updateWith.ClientCertificateKey
				am.ClientCertificate = updateWith.ClientCertificate
				am.ClientCertificateKeyHmac = updateWith.ClientCertificateKeyHmac
				am.AccountAttributeMaps = updateWith.AccountAttributeMaps
				am.DereferenceAliases = updateWith.DereferenceAliases
				return am
			},
		},
		{
			name: "update-just-binddn",
			ctx:  testCtx,
			repo: testRepo,
			setup: func() *AuthMethod {
				return TestAuthMethod(t,
					testConn, databaseWrapper,
					org.PublicId,
					[]string{"ldaps://ldap1", "ldap://ldap2"},
					WithBindCredential(testCtx, "orig-bind-dn", "orig-bind-password"),
				)
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				am := AllocAuthMethod()
				am.PublicId = orig.PublicId
				am.BindDn = "bind-dn"
				return &am
			},
			fieldMasks: []string{
				BindDnField,
			},
			version: 1,
			want: func(orig, updateWith *AuthMethod) *AuthMethod {
				am := orig.clone()
				am.BindDn = updateWith.BindDn
				return am
			},
		},
		{
			name: "update-just-bind-password",
			ctx:  testCtx,
			repo: testRepo,
			setup: func() *AuthMethod {
				return TestAuthMethod(t,
					testConn, databaseWrapper,
					org.PublicId,
					[]string{"ldaps://ldap1", "ldap://ldap2"},
					WithBindCredential(testCtx, "orig-bind-dn", "orig-bind-password"),
				)
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				am := AllocAuthMethod()
				am.PublicId = orig.PublicId
				am.BindPassword = "bind-password"
				return &am
			},
			fieldMasks: []string{
				BindPasswordField,
			},
			version: 1,
			want: func(orig, updateWith *AuthMethod) *AuthMethod {
				am := orig.clone()
				am.BindPassword = updateWith.BindPassword
				return am
			},
		},
		{
			name: "missing-auth-method",
			ctx:  testCtx,
			repo: testRepo,
			setup: func() *AuthMethod {
				return nil
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				return orig
			},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing auth method",
		},
		{
			name: "missing-auth-method-store",
			ctx:  testCtx,
			repo: testRepo,
			setup: func() *AuthMethod {
				return &AuthMethod{}
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				return orig
			},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing auth method store",
		},
		{
			name: "missing-public-id",
			ctx:  testCtx,
			repo: testRepo,
			setup: func() *AuthMethod {
				am := AllocAuthMethod()
				return &am
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				return orig
			},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing public id",
		},
		{
			name:       "invalid-field-mask",
			ctx:        testCtx,
			repo:       testRepo,
			fieldMasks: []string{"CreateTime"},
			setup: func() *AuthMethod {
				am := AllocAuthMethod()
				am.PublicId = "test-id"
				return &am
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				return orig
			},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "invalid field mask: \"CreateTime\"",
		},
		{
			name: "no-field-mask",
			ctx:  testCtx,
			repo: testRepo,
			setup: func() *AuthMethod {
				am := AllocAuthMethod()
				am.PublicId = "test-id"
				return &am
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				return orig
			},
			wantErrMatch:    errors.T(errors.EmptyFieldMask),
			wantErrContains: "empty field mask",
		},
		{
			name:       "missing-urls",
			ctx:        testCtx,
			repo:       testRepo,
			fieldMasks: []string{"Urls"},
			setup: func() *AuthMethod {
				am := AllocAuthMethod()
				am.PublicId = "test-id"
				return &am
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				return orig
			},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing urls (you cannot delete all of them; there must be at least one)",
		},
		{
			name: "lookup-err",
			ctx:  testCtx,
			repo: func() *Repository {
				conn, mock := db.TestSetupWithMock(t)
				mock.ExpectQuery(`SELECT`).WillReturnError(fmt.Errorf("lookup-err"))
				mockRw := db.New(conn)
				testRepo, err := NewRepository(testCtx, mockRw, mockRw, testKms)
				require.NoError(t, err)
				return testRepo
			}(),
			fieldMasks: []string{"UserDn"},
			setup: func() *AuthMethod {
				am := AllocAuthMethod()
				am.PublicId = "test-id"
				return &am
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				return orig
			},
			wantErrMatch:    errors.T(errors.Unknown),
			wantErrContains: "lookup-err",
		},
		{
			name:       "not-found",
			ctx:        testCtx,
			repo:       testRepo,
			fieldMasks: []string{"UserDn"},
			setup: func() *AuthMethod {
				am := AllocAuthMethod()
				am.PublicId = "test-id"
				return &am
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				return orig
			},
			wantErrMatch:    errors.T(errors.RecordNotFound),
			wantErrContains: "auth method \"test-id\": search issue",
		},
		{
			name:       "version-mismatch",
			ctx:        testCtx,
			repo:       testRepo,
			fieldMasks: []string{"UserDn"},
			setup: func() *AuthMethod {
				am := TestAuthMethod(t, testConn, databaseWrapper, org.PublicId, []string{"ldaps://ldap1"})
				am.Version += 1
				return am
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				return orig
			},
			wantErrMatch:    errors.T(errors.Integrity),
			wantErrContains: "update version 0 doesn't match db version 1",
		},
		{
			name: "getWrapper-err",
			ctx:  testCtx,
			repo: func() *Repository {
				testKms := &kms.MockGetWrapperer{
					GetErr: fmt.Errorf("getWrapper-err"),
				}
				testRepo, err := NewRepository(testCtx, testRw, testRw, testKms)
				require.NoError(t, err)
				return testRepo
			}(),
			version:    1,
			fieldMasks: []string{"UserDn"},
			setup: func() *AuthMethod {
				return TestAuthMethod(t, testConn, databaseWrapper, org.PublicId, []string{"ldaps://ldap1"})
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				return orig
			},
			wantErrMatch:    errors.T(errors.Unknown),
			wantErrContains: "getWrapper-err",
		},
		{
			name:       "urls-conversion-err",
			ctx:        testCtx,
			repo:       testRepo,
			version:    1,
			fieldMasks: []string{"Urls"},
			setup: func() *AuthMethod {
				am := TestAuthMethod(t, testConn, databaseWrapper, org.PublicId, []string{"ldaps://ldap1"})
				am.Urls = []string{"https://not-valid.com"}
				return am
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				return orig
			},
			wantErrMatch:    errors.T(errors.Unknown),
			wantErrContains: "valueObjectChanges: ldap.NewUrl: scheme \"https\" is not ldap or ldaps",
		},
		{
			name:       "certs-conversion-err",
			ctx:        testCtx,
			repo:       testRepo,
			version:    1,
			fieldMasks: []string{"Certificates"},
			setup: func() *AuthMethod {
				am := TestAuthMethod(t, testConn, databaseWrapper, org.PublicId, []string{"ldaps://ldap1"})
				am.Certificates = []string{TestInvalidPem}
				return am
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				return orig
			},
			wantErrMatch:    errors.T(errors.Unknown),
			wantErrContains: "valueObjectChanges: ldap.NewCertificate: failed to parse certificate",
		},
		{
			name:       "account-maps-conversion-err",
			ctx:        testCtx,
			repo:       testRepo,
			version:    1,
			fieldMasks: []string{AccountAttributeMapsField},
			setup: func() *AuthMethod {
				am := TestAuthMethod(t, testConn, databaseWrapper, org.PublicId, []string{"ldaps://ldap1"})
				am.AccountAttributeMaps = []string{"invalid-map"}
				return am
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				return orig
			},
			wantErrMatch:    errors.T(errors.Unknown),
			wantErrContains: "ldap.ParseAccountAttributeMaps: error parsing attribute",
		},
		{
			name:       "use-token-groups-update",
			ctx:        testCtx,
			repo:       testRepo,
			version:    1,
			fieldMasks: []string{"UseTokenGroups"},
			setup: func() *AuthMethod {
				am := TestAuthMethod(t, testConn, databaseWrapper, org.PublicId, []string{"ldaps://ldap1"})
				return am
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				am := orig.clone()
				am.UseTokenGroups = true
				return am
			},
			want: func(orig, updateWith *AuthMethod) *AuthMethod {
				am := orig.clone()
				am.UseTokenGroups = true
				return am
			},
		},
		{
			name:       "use-token-groups-update-false",
			ctx:        testCtx,
			repo:       testRepo,
			version:    1,
			fieldMasks: []string{"UseTokenGroups"},
			setup: func() *AuthMethod {
				am := TestAuthMethod(t, testConn, databaseWrapper, org.PublicId, []string{"ldaps://ldap1"}, WithUseTokenGroups(testCtx))
				return am
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				am := orig.clone()
				am.UseTokenGroups = false
				return am
			},
			want: func(orig, updateWith *AuthMethod) *AuthMethod {
				am := orig.clone()
				am.UseTokenGroups = false
				return am
			},
		},
		{
			name:       "start-tls-false",
			ctx:        testCtx,
			repo:       testRepo,
			version:    1,
			fieldMasks: []string{"StartTls"},
			setup: func() *AuthMethod {
				am := TestAuthMethod(t, testConn, databaseWrapper, org.PublicId, []string{"ldaps://ldap1"}, WithStartTLS(testCtx))
				return am
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				am := orig.clone()
				am.StartTls = false
				return am
			},
			want: func(orig, updateWith *AuthMethod) *AuthMethod {
				am := orig.clone()
				am.StartTls = false
				return am
			},
		},
		{
			name:       "user-dn-update",
			ctx:        testCtx,
			repo:       testRepo,
			version:    1,
			fieldMasks: []string{"UserDn"},
			setup: func() *AuthMethod {
				am := TestAuthMethod(t, testConn, databaseWrapper, org.PublicId, []string{"ldaps://ldap1"}, WithUserDn(testCtx, "orig-user-dn"))
				return am
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				am := orig.clone()
				am.UserDn = "updated-user-dn"
				return am
			},
			want: func(orig, updateWith *AuthMethod) *AuthMethod {
				am := orig.clone()
				am.UserDn = "updated-user-dn"
				return am
			},
		},
		{
			name:       "user-attr-update",
			ctx:        testCtx,
			repo:       testRepo,
			version:    1,
			fieldMasks: []string{"UserAttr"},
			setup: func() *AuthMethod {
				am := TestAuthMethod(t, testConn, databaseWrapper, org.PublicId, []string{"ldaps://ldap1"}, WithUserDn(testCtx, "orig-user-dn"), WithUserAttr(testCtx, "orig-user-attr"))
				return am
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				am := orig.clone()
				am.UserAttr = "updated-user-attr"
				return am
			},
			want: func(orig, updateWith *AuthMethod) *AuthMethod {
				am := orig.clone()
				am.UserAttr = "updated-user-attr"
				am.UserDn = "orig-user-dn"
				return am
			},
		},
		{
			name:       "user-filter-update",
			ctx:        testCtx,
			repo:       testRepo,
			version:    1,
			fieldMasks: []string{"UserFilter"},
			setup: func() *AuthMethod {
				am := TestAuthMethod(t, testConn, databaseWrapper, org.PublicId, []string{"ldaps://ldap1"}, WithUserFilter(testCtx, "orig-user-filter"))
				return am
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				am := orig.clone()
				am.UserFilter = "updated-user-filter"
				return am
			},
			want: func(orig, updateWith *AuthMethod) *AuthMethod {
				am := orig.clone()
				am.UserFilter = "updated-user-filter"
				return am
			},
		},
		{
			name:       "enable-groups-err",
			ctx:        testCtx,
			repo:       testRepo,
			version:    1,
			fieldMasks: []string{"EnableGroups"},
			setup: func() *AuthMethod {
				am := TestAuthMethod(t, testConn, databaseWrapper, org.PublicId, []string{"ldaps://ldap1"})
				return am
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				am := orig.clone()
				am.EnableGroups = true
				return am
			},
			wantErrMatch:    errors.T(errors.Integrity),
			wantErrContains: "must have a configured group_dn when enable_groups = true and use_token_groups = false",
		},
		{
			name:       "group-dn-update",
			ctx:        testCtx,
			repo:       testRepo,
			version:    1,
			fieldMasks: []string{"GroupDn"},
			setup: func() *AuthMethod {
				am := TestAuthMethod(t, testConn, databaseWrapper, org.PublicId, []string{"ldaps://ldap1"}, WithUserDn(testCtx, "orig-group-dn"))
				return am
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				am := orig.clone()
				am.GroupDn = "updated-group-dn"
				return am
			},
			want: func(orig, updateWith *AuthMethod) *AuthMethod {
				am := orig.clone()
				am.GroupDn = "updated-group-dn"
				return am
			},
		},
		{
			name:       "group-attr-update",
			ctx:        testCtx,
			repo:       testRepo,
			version:    1,
			fieldMasks: []string{"GroupAttr"},
			setup: func() *AuthMethod {
				am := TestAuthMethod(t, testConn, databaseWrapper, org.PublicId, []string{"ldaps://ldap1"}, WithGroupDn(testCtx, "orig-group-dn"), WithGroupAttr(testCtx, "orig-group-attr"))
				return am
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				am := orig.clone()
				am.GroupAttr = "updated-group-attr"
				return am
			},
			want: func(orig, updateWith *AuthMethod) *AuthMethod {
				am := orig.clone()
				am.GroupAttr = "updated-group-attr"
				return am
			},
		},
		{
			name:       "group-filter-update",
			ctx:        testCtx,
			repo:       testRepo,
			version:    1,
			fieldMasks: []string{"GroupAttr"},
			setup: func() *AuthMethod {
				am := TestAuthMethod(t, testConn, databaseWrapper, org.PublicId, []string{"ldaps://ldap1"}, WithGroupDn(testCtx, "orig-group-dn"), WithGroupFilter(testCtx, "orig-group-filter"))
				return am
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				am := orig.clone()
				am.GroupAttr = "updated-group-filter"
				return am
			},
			want: func(orig, updateWith *AuthMethod) *AuthMethod {
				am := orig.clone()
				am.GroupAttr = "updated-group-filter"
				return am
			},
		},
		{
			name:       "user-entry-search-conversion-no-update",
			ctx:        testCtx,
			repo:       testRepo,
			version:    1,
			fieldMasks: []string{"UserDn"},
			setup: func() *AuthMethod {
				am := TestAuthMethod(t, testConn, databaseWrapper, org.PublicId, []string{"ldaps://ldap1"})
				return am
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				return orig
			},
			want: func(orig, updateWith *AuthMethod) *AuthMethod {
				return orig.clone()
			},
			wantNoRowsUpdated: true,
		},
		{
			name:       "group-entry-search-conversion-no-update",
			ctx:        testCtx,
			repo:       testRepo,
			version:    1,
			fieldMasks: []string{"GroupDn"},
			setup: func() *AuthMethod {
				am := TestAuthMethod(t, testConn, databaseWrapper, org.PublicId, []string{"ldaps://ldap1"})
				return am
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				return orig
			},
			want: func(orig, updateWith *AuthMethod) *AuthMethod {
				return orig.clone()
			},
			wantNoRowsUpdated: true,
		},
		{
			name:       "client-search-conversion-no-update",
			ctx:        testCtx,
			repo:       testRepo,
			version:    1,
			fieldMasks: []string{"ClientCertificate"},
			setup: func() *AuthMethod {
				am := TestAuthMethod(t, testConn, databaseWrapper, org.PublicId, []string{"ldaps://ldap1"})
				return am
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				return orig
			},
			want: func(orig, updateWith *AuthMethod) *AuthMethod {
				return orig.clone()
			},
			wantNoRowsUpdated: true,
		},
		{
			name:       "bind-credential-conversion-no-update",
			ctx:        testCtx,
			repo:       testRepo,
			version:    1,
			fieldMasks: []string{"BindDn"},
			setup: func() *AuthMethod {
				am := TestAuthMethod(t, testConn, databaseWrapper, org.PublicId, []string{"ldaps://ldap1"})
				return am
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				return orig
			},
			want: func(orig, updateWith *AuthMethod) *AuthMethod {
				return orig.clone()
			},
			wantNoRowsUpdated: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			orig := tc.setup()
			updateWith := tc.updateWith(orig)
			updated, rowsUpdated, err := tc.repo.UpdateAuthMethod(tc.ctx, updateWith, tc.version, tc.fieldMasks, tc.opt...)
			if tc.wantErrMatch != nil {
				require.Error(err)
				assert.Empty(updated)
				assert.Zero(rowsUpdated)
				assert.Truef(errors.Match(tc.wantErrMatch, err), "want err code: %q got: %q", tc.wantErrMatch.Code, err)
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			require.NotNil(updated)
			require.NotNil(tc.want)
			want := tc.want(orig, updateWith)
			want.CreateTime = updated.CreateTime
			want.UpdateTime = updated.UpdateTime
			want.Version = updated.Version
			want.BindPasswordHmac = updated.BindPasswordHmac
			want.ClientCertificateKeyHmac = updated.ClientCertificateKeyHmac
			TestSortAuthMethods(t, []*AuthMethod{want, updated})
			assert.Empty(cmp.Diff(updated.AuthMethod, want.AuthMethod, protocmp.Transform()))
			if !tc.wantNoRowsUpdated {
				assert.Equal(1, rowsUpdated)
				err = db.TestVerifyOplog(t, testRw, updateWith.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
				require.NoErrorf(err, "unexpected error verifying oplog entry: %s", err)
			}
			found, err := tc.repo.LookupAuthMethod(tc.ctx, want.PublicId)
			require.NoError(err)
			TestSortAuthMethods(t, []*AuthMethod{found})
			assert.Empty(cmp.Diff(found.AuthMethod, want.AuthMethod, protocmp.Transform()))
		})
	}
}

func Test_validateFieldMask(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		fieldMask []string
		wantErr   bool
	}{
		{
			name: "all-valid-fields",
			fieldMask: []string{
				NameField,
				DescriptionField,
				StartTlsField,
				InsecureTlsField,
				DiscoverDnField,
				AnonGroupSearchField,
				UpnDomainField,
				UrlsField,
				UserDnField,
				UserAttrField,
				UserFilterField,
				GroupDnField,
				GroupAttrField,
				GroupFilterField,
				CertificatesField,
				ClientCertificateField,
				ClientCertificateKeyField,
				BindDnField,
				BindPasswordField,
				AccountAttributeMapsField,
			},
		},
		{
			name:      "invalid",
			fieldMask: []string{"Invalid", NameField},
			wantErr:   true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			err := validateFieldMask(context.TODO(), tc.fieldMask)
			if tc.wantErr {
				require.Error(err)
				return
			}
			require.NoError(err)
		})
	}
}

// Test_valueObjectChanges is just being used to test failure conditions primarily
func Test_valueObjectChanges(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	_, pem1 := TestGenerateCA(t, "localhost")
	_, pem2 := TestGenerateCA(t, "127.0.0.1")
	_, pem3 := TestGenerateCA(t, "www.example.com")

	tests := []struct {
		name            string
		ctx             context.Context
		id              string
		voName          voName
		new             []string
		old             []string
		dbMask          []string
		nullFields      []string
		wantAdd         []any
		wantDel         []any
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name:            "missing-public-id",
			ctx:             testCtx,
			voName:          CertificateVO,
			new:             nil,
			old:             []string{pem1, pem2, pem3},
			nullFields:      []string{string(CertificateVO)},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing public id",
		},
		{
			name:            "invalid-vo-name",
			ctx:             testCtx,
			voName:          voName("invalid-name"),
			id:              "am-public-id",
			new:             nil,
			old:             []string{pem1, pem2},
			nullFields:      []string{string(CertificateVO)},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "invalid value object name",
		},
		{
			name:            "dup-new",
			ctx:             testCtx,
			id:              "am-public-id",
			voName:          CertificateVO,
			new:             []string{pem1, pem1},
			old:             []string{pem1},
			dbMask:          []string{string(CertificateVO)},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "duplicate new Certificates",
		},
		{
			name:            "dup-old",
			ctx:             testCtx,
			id:              "am-public-id",
			voName:          CertificateVO,
			new:             []string{pem1},
			old:             []string{pem2, pem2},
			dbMask:          []string{string(CertificateVO)},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "duplicate old Certificates",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			gotAdd, gotDel, err := valueObjectChanges(tc.ctx, tc.id, tc.voName, tc.new, tc.old, tc.dbMask, tc.nullFields)
			if tc.wantErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tc.wantErrMatch, err), "want err code: %q got: %q", tc.wantErrMatch.Code, err)
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			assert.Equal(tc.wantAdd, gotAdd)

			switch tc.voName {
			case CertificateVO:
				sort.Slice(gotDel, func(a, b int) bool {
					aa := gotDel[a]
					bb := gotDel[b]
					return aa.(*Certificate).Cert < bb.(*Certificate).Cert
				})
			case UrlVO:
				sort.Slice(gotDel, func(a, b int) bool {
					aa := gotDel[a]
					bb := gotDel[b]
					return aa.(*Url).ServerUrl < bb.(*Url).ServerUrl
				})
			case AccountAttributeMapsVO:
				sort.Slice(gotDel, func(a, b int) bool {
					aa := gotDel[a]
					bb := gotDel[b]
					return aa.(*AccountAttributeMap).ToAttribute < bb.(*AccountAttributeMap).ToAttribute
				})
			}
			assert.Equalf(tc.wantDel, gotDel, "wantDel: %s\ngotDel:  %s\n", tc.wantDel, gotDel)
		})
	}
}
