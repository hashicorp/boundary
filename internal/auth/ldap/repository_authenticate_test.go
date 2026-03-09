// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ldap

import (
	"context"
	"database/sql/driver"
	"encoding/pem"
	"fmt"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/auth/ldap/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/cap/ldap"
	"github.com/hashicorp/go-hclog"
	"github.com/jimlambrt/gldap"
	"github.com/jimlambrt/gldap/testdirectory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestRepository_authenticate(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()

	rootWrapper := db.TestWrapper(t)

	testConn, _ := db.TestSetup(t, "postgres")
	testRw := db.New(testConn)

	testKms := kms.TestKms(t, testConn, rootWrapper)

	testRepo, err := NewRepository(testCtx, testRw, testRw, testKms)
	require.NoError(t, err)

	iamRepo := iam.TestRepo(t, testConn, rootWrapper)
	org, _ := iam.TestScopes(t, iamRepo)
	orgDbWrapper, err := testKms.GetWrapper(testCtx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	logger := hclog.New(&hclog.LoggerOptions{
		Name:  "test-logger",
		Level: hclog.Error,
	})
	td := testdirectory.Start(t,
		testdirectory.WithDefaults(t, &testdirectory.Defaults{AllowAnonymousBind: true}),
		testdirectory.WithLogger(t, logger),
	)
	tdCerts, err := ParseCertificates(testCtx, td.Cert())
	require.NoError(t, err)

	testAm := TestAuthMethod(t, testConn, orgDbWrapper, org.PublicId,
		[]string{fmt.Sprintf("ldaps://%s:%d", td.Host(), td.Port())},
		WithCertificates(testCtx, tdCerts...),
		WithDiscoverDn(testCtx),
		WithEnableGroups(testCtx),
		WithUserDn(testCtx, testdirectory.DefaultUserDN),
		WithGroupDn(testCtx, testdirectory.DefaultGroupDN),
	)

	testAmAccAttrs := TestAuthMethod(t, testConn, orgDbWrapper, org.PublicId,
		[]string{fmt.Sprintf("ldaps://%s:%d", td.Host(), td.Port())},
		WithCertificates(testCtx, tdCerts...),
		WithDiscoverDn(testCtx),
		WithEnableGroups(testCtx),
		WithUserDn(testCtx, testdirectory.DefaultUserDN),
		WithGroupDn(testCtx, testdirectory.DefaultGroupDN),
		WithAccountAttributeMap(testCtx, map[string]AccountToAttribute{
			"fn": "fullName",
			"at": "email",
		}),
	)

	const (
		testLoginName = "alice"
		testPassword  = "password"
	)

	testAccount := TestAccount(t, testConn, testAm, testLoginName)
	testAccountAccAttrs := TestAccount(t, testConn, testAmAccAttrs, testLoginName)

	groups := []*gldap.Entry{
		testdirectory.NewGroup(t, "admin", []string{"alice"}),
		testdirectory.NewGroup(t, "admin", []string{"eve"}, testdirectory.WithDefaults(t, &testdirectory.Defaults{UPNDomain: "example.com"})),
	}
	tokenGroups := map[string][]*gldap.Entry{
		"S-1-1": {
			testdirectory.NewGroup(t, "admin-token-group", []string{"alice"}),
		},
	}
	sidBytes, err := ldap.SIDBytes(1, 1)
	require.NoError(t, err)
	users := testdirectory.NewUsers(t, []string{"alice", "bob"}, testdirectory.WithMembersOf(t, "admin"), testdirectory.WithTokenGroups(t, sidBytes))
	users = append(
		users,
		testdirectory.NewUsers(
			t,
			[]string{"eve"},
			testdirectory.WithDefaults(t, &testdirectory.Defaults{UPNDomain: "example.com"}),
			testdirectory.WithMembersOf(t, "admin"))...,
	)
	// add some attributes that we always want to filter out of an AuthResult,
	// so if we ever start seeing tests fail because of them; we know that we've
	// messed up the default filtering
	for _, u := range users {
		u.Attributes = append(u.Attributes,
			gldap.NewEntryAttribute(ldap.DefaultADUserPasswordAttribute, []string{"password"}),
			gldap.NewEntryAttribute(ldap.DefaultOpenLDAPUserPasswordAttribute, []string{"password"}),
			gldap.NewEntryAttribute("fullName", []string{"test-full-name"}),
			gldap.NewEntryAttribute("fn", []string{"test-fn"}),
			gldap.NewEntryAttribute("at", []string{"testat@email.com"}),
		)
	}
	td.SetUsers(users...)
	td.SetGroups(groups...)
	td.SetTokenGroups(tokenGroups)

	tests := []struct {
		name            string
		ctx             context.Context
		repo            *Repository
		authMethodId    string
		loginName       string
		password        string
		want            func(got *Account) *Account
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name:         "success-existing-account",
			ctx:          testCtx,
			repo:         testRepo,
			authMethodId: testAm.PublicId,
			loginName:    testAccount.LoginName,
			password:     testPassword,
			want: func(got *Account) *Account {
				a := &Account{Account: &store.Account{
					AuthMethodId:   testAm.PublicId,
					ScopeId:        testAccount.ScopeId,
					PublicId:       testAccount.PublicId,
					Version:        testAccount.Version,
					Dn:             "cn=alice,ou=people,dc=example,dc=org",
					Email:          "alice@example.com",
					FullName:       "test-full-name",
					LoginName:      "alice",
					MemberOfGroups: "[\"cn=admin,ou=groups,dc=example,dc=org\"]",
				}}
				return a
			},
		},
		{
			name:         "success-with-account-acc-attrs",
			ctx:          testCtx,
			repo:         testRepo,
			authMethodId: testAmAccAttrs.PublicId,
			loginName:    testAccountAccAttrs.LoginName,
			password:     testPassword,
			want: func(got *Account) *Account {
				a := &Account{Account: &store.Account{
					AuthMethodId:   testAmAccAttrs.PublicId,
					ScopeId:        testAccountAccAttrs.ScopeId,
					PublicId:       testAccountAccAttrs.PublicId,
					Version:        testAccountAccAttrs.Version,
					Dn:             "cn=alice,ou=people,dc=example,dc=org",
					Email:          "testat@email.com",
					FullName:       "test-fn",
					LoginName:      "alice",
					MemberOfGroups: "[\"cn=admin,ou=groups,dc=example,dc=org\"]",
				}}
				return a
			},
		},
		{
			name:         "success-new-account-with-no-groups",
			ctx:          testCtx,
			repo:         testRepo,
			authMethodId: testAm.PublicId,
			loginName:    "bob",
			password:     testPassword,
			want: func(got *Account) *Account {
				a := &Account{Account: &store.Account{
					AuthMethodId: testAm.PublicId,
					ScopeId:      testAm.ScopeId,
					PublicId:     got.PublicId,
					Version:      got.Version,
					Dn:           "cn=bob,ou=people,dc=example,dc=org",
					Email:        "bob@example.com",
					FullName:     "test-full-name",
					LoginName:    "bob",
				}}
				return a
			},
		},
		{
			name:            "missing-auth-method-id",
			ctx:             testCtx,
			repo:            testRepo,
			loginName:       "alice",
			password:        testPassword,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing auth method id",
		},
		{
			name:            "missing-login-name",
			ctx:             testCtx,
			repo:            testRepo,
			authMethodId:    testAm.PublicId,
			password:        testPassword,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing login name",
		},
		{
			name:            "missing-password",
			ctx:             testCtx,
			repo:            testRepo,
			authMethodId:    testAm.PublicId,
			loginName:       "alice",
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing password",
		},
		{
			name:            "auth-method-id-not-found",
			ctx:             testCtx,
			repo:            testRepo,
			authMethodId:    "auth-method-id-not-found",
			loginName:       "alice",
			password:        testPassword,
			wantErrMatch:    errors.T(errors.RecordNotFound),
			wantErrContains: "auth method id \"auth-method-id-not-found\" not found",
		},
		{
			name: "auth-method-id-lookup-err",
			ctx:  testCtx,
			repo: func() *Repository {
				conn, mock := db.TestSetupWithMock(t)
				mock.ExpectQuery(`SELECT`).WillReturnError(fmt.Errorf("auth-method-id-lookup-err"))
				rw := db.New(conn)
				r, err := NewRepository(testCtx, rw, rw, testKms)
				require.NoError(t, err)
				return r
			}(),
			authMethodId:    testAm.PublicId,
			loginName:       "alice",
			password:        testPassword,
			wantErrMatch:    errors.T(errors.Unknown),
			wantErrContains: "auth-method-id-lookup-err",
		},
		{
			name: "invalid-attribute-maps",
			ctx:  testCtx,
			repo: func() *Repository {
				conn, mock := db.TestSetupWithMock(t)
				mock.ExpectQuery("SELECT").WillReturnRows(sqlmock.NewRows(
					[]string{
						"is_primary_auth_method",
						"public_id",
						"scope_id",
						"name",
						"description",
						"create_time",
						"update_time",
						"version",
						"state",
						"start_tls",
						"insecure_tls",
						"discover_dn",
						"anon_group_search",
						"upn_domain",
						"enable_groups",
						"use_token_groups",
						"maximum_page_size",
						"urls",
						"certs",
						"account_attribute_map",
						"user_dn",
						"user_attr",
						"user_filter",
						"group_dn",
						"group_attr",
						"group_filter",
						"client_certificate_key",
						"client_certificate_key_hmac",
						"client_certificate_key_id",
						"client_certificate_cert",
						"bind_dn",
						"bind_password",
						"bind_password_hmac",
						"bind_password_key_id",
						"dereference_aliases",
					},
				).AddRow(
					"f",
					"amldap_badattrs",
					"o_1234567890",
					nil,
					nil,
					"2024-05-15 17:40:31.327736+00",
					"2024-05-15 17:40:31.327736+00",
					1,
					"inactive",
					"f",
					"f",
					"t",
					"f",
					nil,
					"t",
					"f",
					0,
					fmt.Sprintf("ldaps://%s:%d", td.Host(), td.Port()),
					func() driver.Value {
						certs, err := EncodeCertificates(testCtx, tdCerts...)
						require.NoError(t, err)
						return certs[0]
					}(),
					"at=email|fn=fullName|bad=invalidAttribute",
					"ou=people,dc=example,dc=org",
					nil,
					nil,
					"ou=groups,dc=example,dc=org",
					nil,
					nil,
					nil,
					nil,
					nil,
					nil,
					nil,
					nil,
					nil,
					nil,
					nil,
				))
				rw := db.New(conn)
				r, err := NewRepository(testCtx, rw, rw, testKms)
				require.NoError(t, err)
				return r
			}(),
			authMethodId:    "amldap_badattrs",
			loginName:       "alice",
			password:        testPassword,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: `failed to convert account attribute maps: ldap.(AuthMethod).convertAccountAttributeMaps: ldap.ParseAccountAttributeMaps: ldap.ConvertToAccountToAttribute: "invalidAttribute" is not a valid ToAccountAttribute value ("email", "fullName")`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := tc.repo.Authenticate(tc.ctx, tc.authMethodId, tc.loginName, tc.password)
			if tc.wantErrMatch != nil {
				require.Error(err)
				assert.Nil(got)
				assert.Truef(errors.Match(tc.wantErrMatch, err), "unexpected error: %s", err.Error())
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			require.NotNil(tc.want)
			assert.NotEmpty(got.UpdateTime)
			assert.NotEmpty(got.CreateTime)
			w := tc.want(got)
			w.UpdateTime = got.UpdateTime
			w.CreateTime = got.CreateTime
			assert.Empty(cmp.Diff(w, got, protocmp.Transform()))
		})
	}
	t.Run("use-token-groups", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		amWithTokenGroups := TestAuthMethod(t, testConn, orgDbWrapper, org.PublicId,
			[]string{fmt.Sprintf("ldaps://%s:%d", td.Host(), td.Port())},
			WithCertificates(testCtx, tdCerts...),
			WithDiscoverDn(testCtx),
			WithEnableGroups(testCtx),
			WithUserDn(testCtx, testdirectory.DefaultUserDN),
			WithUseTokenGroups(testCtx),
		)

		got, err := testRepo.Authenticate(testCtx, amWithTokenGroups.PublicId, testLoginName, testPassword)
		require.NoError(err)
		assert.NotNil(got)
		assert.NotEmpty(got.UpdateTime)
		assert.NotEmpty(got.CreateTime)
		w := &Account{Account: &store.Account{
			AuthMethodId:   amWithTokenGroups.PublicId,
			ScopeId:        amWithTokenGroups.ScopeId,
			PublicId:       got.PublicId,
			Version:        got.Version,
			Dn:             "cn=alice,ou=people,dc=example,dc=org",
			Email:          "alice@example.com",
			FullName:       "test-full-name",
			LoginName:      "alice",
			MemberOfGroups: "[\"cn=admin-token-group,ou=groups,dc=example,dc=org\"]",
		}}
		w.UpdateTime = got.UpdateTime
		w.CreateTime = got.CreateTime
		assert.Empty(cmp.Diff(w, got, protocmp.Transform()))
	})
	t.Run("authenticate-err", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		amWithNoCerts := TestAuthMethod(t, testConn, orgDbWrapper, org.PublicId,
			[]string{fmt.Sprintf("ldaps://%s:%d", td.Host(), td.Port())},
			WithDiscoverDn(testCtx),
			WithEnableGroups(testCtx),
			WithUserDn(testCtx, testdirectory.DefaultUserDN),
			WithGroupDn(testCtx, testdirectory.DefaultGroupDN),
		)
		got, err := testRepo.Authenticate(testCtx, amWithNoCerts.PublicId, testLoginName, testPassword)
		require.Error(err)
		assert.Contains(err.Error(), "authenticate failed")
		assert.Contains(err.Error(), "failed to connect")
		assert.Nil(got)
	})
	t.Run("mTLS-client-success", func(t *testing.T) {
		// test for client key/cert issue reported:
		// https://github.com/hashicorp/boundary/issues/3927
		tdWithMtls := testdirectory.Start(t,
			testdirectory.WithMTLS(t),
			testdirectory.WithDefaults(t, &testdirectory.Defaults{AllowAnonymousBind: true}),
			testdirectory.WithLogger(t, logger),
		)
		tdWithMtlsCerts, err := ParseCertificates(testCtx, tdWithMtls.Cert())
		require.NoError(t, err)

		testClientCert, err := ParseCertificates(testCtx, tdWithMtls.ClientCert())
		require.NoError(t, err)
		testClientKeyPem := tdWithMtls.ClientKey()
		block, _ := pem.Decode([]byte(testClientKeyPem))
		require.NotEmpty(t, block)
		// block.Bytes

		testAmWithMtls := TestAuthMethod(t, testConn, orgDbWrapper, org.PublicId,
			[]string{fmt.Sprintf("ldaps://%s:%d", tdWithMtls.Host(), tdWithMtls.Port())},
			WithCertificates(testCtx, tdWithMtlsCerts...),
			WithClientCertificate(testCtx, block.Bytes, testClientCert[0]),
			WithDiscoverDn(testCtx),
			WithEnableGroups(testCtx),
			WithUserDn(testCtx, testdirectory.DefaultUserDN),
			WithGroupDn(testCtx, testdirectory.DefaultGroupDN),
		)

		testAccountUsingMtls := TestAccount(t, testConn, testAmWithMtls, testLoginName)

		tdWithMtls.SetUsers(users...)
		tdWithMtls.SetGroups(groups...)
		tdWithMtls.SetTokenGroups(tokenGroups)

		got, err := testRepo.Authenticate(testCtx, testAmWithMtls.PublicId, testAccountUsingMtls.LoginName, testPassword)
		require.NoError(t, err)
		require.NotEmpty(t, got)
	})
}

func Test_caseInsensitiveAttributeSearch(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)

	found, values := caseInsensitiveAttributeSearch("fullName", map[string][]string{"fullName": {"eve"}})
	assert.True(found)
	assert.Equal([]string{"eve"}, values)

	found, values = caseInsensitiveAttributeSearch("preferredName", map[string][]string{"fullName": {"eve"}})
	assert.False(found)
	assert.Empty(values)
}
