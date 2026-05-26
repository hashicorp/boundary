// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package ldap

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"net/url"
	"sort"
	"testing"

	"github.com/hashicorp/boundary/internal/auth/ldap/store"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestNewAuthMethod(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	testCert, testCertEncoded := TestGenerateCA(t, "localhost")
	_, testPrivKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	derPrivKey, err := x509.MarshalPKCS8PrivateKey(testPrivKey)
	require.NoError(t, err)

	tests := []struct {
		name            string
		ctx             context.Context
		scopeId         string
		urls            []*url.URL
		opts            []Option
		want            *AuthMethod
		wantErr         bool
		wantErrCode     errors.Code
		wantErrContains string
	}{
		{
			name:    "valid-all-opts",
			ctx:     testCtx,
			scopeId: "global",
			urls:    TestConvertToUrls(t, "ldaps://alice.com"), // converted to an option
			opts: []Option{
				WithName(testCtx, "test-name"),
				WithDescription(testCtx, "test-description"),
				WithStartTLS(testCtx),
				WithInsecureTLS(testCtx),
				WithDiscoverDn(testCtx),
				WithAnonGroupSearch(testCtx),
				WithUpnDomain(testCtx, "alice.com"),
				WithUserDn(testCtx, "user-dn"),
				WithUserAttr(testCtx, "user-attr"),
				WithUserFilter(testCtx, "user-filter"),
				WithGroupDn(testCtx, "group-dn"),
				WithEnableGroups(testCtx),
				WithGroupAttr(testCtx, "group-attr"),
				WithGroupFilter(testCtx, "group-filter"),
				WithBindCredential(testCtx, "bind-dn", "bind-password"),
				WithCertificates(testCtx, testCert),
				WithClientCertificate(testCtx, derPrivKey, testCert), // not a client cert but good enough for this test.
				WithAccountAttributeMap(testCtx, map[string]AccountToAttribute{"mail": "email"}),
				WithDerefAliases(testCtx, DerefAlways),
				WithMaximumPageSize(testCtx, 10),
			},
			want: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					ScopeId:              "global",
					Urls:                 []string{"ldaps://alice.com"},
					OperationalState:     string(InactiveState),
					Name:                 "test-name",
					Description:          "test-description",
					StartTls:             true,
					InsecureTls:          true,
					DiscoverDn:           true,
					AnonGroupSearch:      true,
					UpnDomain:            "alice.com",
					UserDn:               "user-dn",
					UserAttr:             "user-attr",
					UserFilter:           "user-filter",
					EnableGroups:         true,
					GroupDn:              "group-dn",
					GroupAttr:            "group-attr",
					GroupFilter:          "group-filter",
					BindDn:               "bind-dn",
					BindPassword:         "bind-password",
					Certificates:         []string{testCertEncoded},
					ClientCertificate:    testCertEncoded,
					ClientCertificateKey: derPrivKey,
					AccountAttributeMaps: []string{"mail=email"},
					DereferenceAliases:   string(DerefAlways),
					MaximumPageSize:      10,
				},
			},
		},
		{
			name:    "valid-no-opts",
			ctx:     testCtx,
			scopeId: "global",
			urls:    TestConvertToUrls(t, "ldaps://alice.com"),
			want: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					ScopeId:          "global",
					Urls:             []string{"ldaps://alice.com"},
					OperationalState: string(InactiveState),
				},
			},
		},
		{
			name:            "missing-scope",
			ctx:             testCtx,
			urls:            TestConvertToUrls(t, "ldaps://alice.com"),
			wantErr:         true,
			wantErrCode:     errors.InvalidParameter,
			wantErrContains: "missing scope id",
		},
		{
			name:    "invalid-urls",
			ctx:     testCtx,
			scopeId: "global",
			urls: func() []*url.URL {
				parsed, err := url.Parse("https://alice.com")
				require.NoError(t, err)
				return []*url.URL{parsed}
			}(),
			wantErr:         true,
			wantErrCode:     errors.InvalidParameter,
			wantErrContains: `https scheme in url "https://alice.com" is not either ldap or ldaps`,
		},
		{
			name:    "invalid-deref-aliases",
			ctx:     testCtx,
			scopeId: "global",
			urls:    TestConvertToUrls(t, "ldaps://alice.com"),
			opts: []Option{
				WithDerefAliases(testCtx, "invalid"),
			},
			wantErr:         true,
			wantErrCode:     errors.InvalidParameter,
			wantErrContains: `"invalid" is not a valid ldap dereference alias type`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			tc.opts = append(tc.opts, WithUrls(tc.ctx, tc.urls...))
			am, err := NewAuthMethod(tc.ctx, tc.scopeId, tc.opts...)
			if tc.wantErr {
				require.Error(err)
				if tc.wantErrCode != errors.Unknown {
					assert.True(errors.Match(errors.T(tc.wantErrCode), err))
				}
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			assert.Equal(tc.want, am)
		})
	}
}

func TestAuthMethod_SetTableName(t *testing.T) {
	t.Parallel()
	defaultTableName := authMethodTableName
	tests := []struct {
		name      string
		setNameTo string
		want      string
	}{
		{
			name:      "new-name",
			setNameTo: "new-name",
			want:      "new-name",
		},
		{
			name:      "reset to default",
			setNameTo: "",
			want:      defaultTableName,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			def := AllocAuthMethod()
			require.Equal(defaultTableName, def.TableName())
			m := AllocAuthMethod()
			m.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, m.TableName())
		})
	}
}

func TestAuthMethod_clone(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	t.Run("valid", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		testCert, _ := TestGenerateCA(t, "localhost")
		_, testPrivKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(err)
		derPrivKey, err := x509.MarshalPKCS8PrivateKey(testPrivKey)
		require.NoError(err)
		am, err := NewAuthMethod(
			testCtx,
			"global",
			WithUrls(testCtx, TestConvertToUrls(t, "ldaps://alice.com")...),
			WithStartTLS(testCtx),
			WithInsecureTLS(testCtx),
			WithDiscoverDn(testCtx),
			WithAnonGroupSearch(testCtx),
			WithUpnDomain(testCtx, "alice.com"),
			WithUserDn(testCtx, "user-dn"),
			WithUserAttr(testCtx, "user-attr"),
			WithUserFilter(testCtx, "user-filter"),
			WithGroupDn(testCtx, "group-dn"),
			WithGroupAttr(testCtx, "group-attr"),
			WithGroupFilter(testCtx, "group-filter"),
			WithBindCredential(testCtx, "bind-dn", "bind-password"),
			WithCertificates(testCtx, testCert),
			WithClientCertificate(testCtx, derPrivKey, testCert), // not a client cert but good enough for this test.
			WithDerefAliases(testCtx, DerefAlways),
			WithMaximumPageSize(testCtx, 10),
		)
		require.NoError(err)
		cp := am.clone()
		assert.True(proto.Equal(cp.AuthMethod, am.AuthMethod))
	})
	t.Run("not-equal", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		am, err := NewAuthMethod(testCtx, "global", WithUrls(testCtx, TestConvertToUrls(t, "ldaps://alice.com")...))
		require.NoError(err)
		am2, err := NewAuthMethod(testCtx, "global", WithUrls(testCtx, TestConvertToUrls(t, "ldaps://bob.com")...))
		require.NoError(err)

		cp := am.clone()
		assert.True(!proto.Equal(cp.AuthMethod, am2.AuthMethod))
	})
}

func TestAuthMethod_oplog(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	testAm, err := NewAuthMethod(testCtx, "global", WithUrls(testCtx, TestConvertToUrls(t, "ldap://ldap1")...))
	testAm.PublicId = "test-public-id"
	require.NoError(t, err)
	tests := []struct {
		name            string
		ctx             context.Context
		am              *AuthMethod
		opType          oplog.OpType
		want            oplog.Metadata
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name:   "create",
			ctx:    testCtx,
			am:     testAm,
			opType: oplog.OpType_OP_TYPE_CREATE,
			want: oplog.Metadata{
				"resource-public-id": {"test-public-id"},
				"scope-id":           {"global"},
				"op-type":            {oplog.OpType_OP_TYPE_CREATE.String()},
				"resource-type":      {"ldap auth method"},
			},
		},
		{
			name:   "update",
			ctx:    testCtx,
			am:     testAm,
			opType: oplog.OpType_OP_TYPE_UPDATE,
			want: oplog.Metadata{
				"resource-public-id": {"test-public-id"},
				"scope-id":           {"global"},
				"op-type":            {oplog.OpType_OP_TYPE_UPDATE.String()},
				"resource-type":      {"ldap auth method"},
			},
		},
		{
			name: "missing-scope-id",
			ctx:  testCtx,
			am: func() *AuthMethod {
				cp := testAm.clone()
				cp.ScopeId = ""
				return cp
			}(),
			opType:          oplog.OpType_OP_TYPE_UPDATE,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing scope id",
		},
		{
			name: "missing-public-id",
			ctx:  testCtx,
			am: func() *AuthMethod {
				cp := testAm.clone()
				cp.PublicId = ""
				return cp
			}(),
			opType:          oplog.OpType_OP_TYPE_UPDATE,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing public id",
		},
		{
			name:            "missing-op-type",
			ctx:             testCtx,
			am:              testAm,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing op type",
		},
		{
			name:            "missing-auth-method",
			ctx:             testCtx,
			opType:          oplog.OpType_OP_TYPE_UPDATE,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing auth method",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := tc.am.oplog(tc.ctx, tc.opType)
			if tc.wantErrMatch != nil {
				require.Error(err)
				assert.Nil(got)
				assert.True(errors.Match(tc.wantErrMatch, err))
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			assert.Equal(tc.want, got)
		})
	}
}

func Test_convertValueObjects(t *testing.T) {
	testCtx := context.TODO()
	testPublicId := "test-id"
	testLdapServers := []string{"ldaps://ldap1.alice.com", "ldaps://ldap2.alice.com", "ldap://[2001:BEEF:0:0:0:1:0:0001]:80"}
	_, pem := TestGenerateCA(t, "localhost")
	testCerts := []string{pem}
	c, err := NewCertificate(testCtx, testPublicId, pem)
	require.NoError(t, err)
	testCertificates := []*Certificate{c}

	testUrls := make([]*Url, 0, len(testLdapServers))
	for priority, uu := range TestConvertToUrls(t, testLdapServers...) {
		u, err := NewUrl(testCtx, testPublicId, priority+1, uu)
		require.NoError(t, err)
		testUrls = append(testUrls, u)
	}

	testAttrMaps := []string{"email_address=email", "display_name=fullName"}
	testAccountAttributeMaps := make([]*AccountAttributeMap, 0, len(testAttrMaps))
	acms, err := ParseAccountAttributeMaps(testCtx, testAttrMaps...)
	require.NoError(t, err)
	for _, m := range acms {
		toAttribute, err := ConvertToAccountToAttribute(testCtx, m.To)
		require.NoError(t, err)
		obj, err := NewAccountAttributeMap(testCtx, testPublicId, m.From, toAttribute)
		require.NoError(t, err)
		testAccountAttributeMaps = append(testAccountAttributeMaps, obj)
	}

	testUserSearchConf, err := NewUserEntrySearchConf(testCtx, testPublicId, WithUserDn(testCtx, "user-dn"), WithUserAttr(testCtx, "user-attr"))
	require.NoError(t, err)

	testGroupSearchConf, err := NewGroupEntrySearchConf(testCtx, testPublicId, WithGroupDn(testCtx, "group-dn"), WithGroupAttr(testCtx, "group-attr"))
	require.NoError(t, err)

	_, testClientCertEncoded := TestGenerateCA(t, "client-cert-host")
	_, testPrivKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	testClientCertKey, err := x509.MarshalPKCS8PrivateKey(testPrivKey)
	require.NoError(t, err)

	testClientCertificate, err := NewClientCertificate(testCtx, testPublicId, testClientCertKey, testClientCertEncoded)
	require.NoError(t, err)

	testBindCredential, err := NewBindCredential(testCtx, testPublicId, "bind-dn", []byte("bind-password"))
	require.NoError(t, err)

	testDerefAliases, err := NewDerefAliases(testCtx, testPublicId, DerefAlways)
	require.NoError(t, err)

	tests := []struct {
		name            string
		am              *AuthMethod
		wantValues      *convertedValues
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name: "success",
			am: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					PublicId:             testPublicId,
					Certificates:         testCerts,
					Urls:                 testLdapServers,
					UserDn:               "user-dn",
					UserAttr:             "user-attr",
					GroupDn:              "group-dn",
					GroupAttr:            "group-attr",
					ClientCertificateKey: testClientCertKey,
					ClientCertificate:    testClientCertEncoded,
					BindDn:               "bind-dn",
					BindPassword:         "bind-password",
					AccountAttributeMaps: testAttrMaps,
					DereferenceAliases:   string(DerefAlways),
				},
			},
			wantValues: &convertedValues{
				Certs:                testCertificates,
				Urls:                 testUrls,
				UserEntrySearchConf:  testUserSearchConf,
				GroupEntrySearchConf: testGroupSearchConf,
				ClientCertificate:    testClientCertificate,
				BindCredential:       testBindCredential,
				AccountAttributeMaps: testAccountAttributeMaps,
				DerefAliases:         testDerefAliases,
			},
		},
		{
			name: "missing-public-id",
			am: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					Certificates:         testCerts,
					Urls:                 testLdapServers,
					UserDn:               "user-dn",
					UserAttr:             "user-attr",
					GroupDn:              "group-dn",
					GroupAttr:            "group-attr",
					ClientCertificateKey: testClientCertKey,
					ClientCertificate:    testClientCertEncoded,
					BindDn:               "bind-dn",
					BindPassword:         "bind-password",
				},
			},
			wantErrMatch: errors.T(errors.InvalidPublicId),
		},
		{
			name: "invalid-to-account-attr-map",
			am: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					PublicId:             testPublicId,
					AccountAttributeMaps: []string{"displayName=invalid-to-attr"},
				},
			},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "not a valid ToAccountAttribute value",
		},
		{
			name: "invalid-account-attr-map-format",
			am: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					PublicId:             testPublicId,
					AccountAttributeMaps: []string{"not-valid"},
				},
			},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "format must be key=value",
		},
		{
			name: "invalid-cert",
			am: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					PublicId:     testPublicId,
					Certificates: []string{TestInvalidPem},
				},
			},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "failed to parse certificate",
		},
		{
			name: "invalid-url-scheme",
			am: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					PublicId: testPublicId,
					Urls:     []string{"https://ldap1"},
				},
			},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "scheme \"https\" is not ldap or ldaps",
		},
		{
			name: "invalid-url-starts-with-space",
			am: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					PublicId: testPublicId,
					Urls:     []string{"  ldaps://ldap1"},
				},
			},
			wantErrMatch:    errors.T(errors.Unknown),
			wantErrContains: "failed to parse address",
		},
		{
			name: "invalid-url-has-invalid-ipv6",
			am: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					PublicId: testPublicId,
					Urls:     []string{"ldaps://[2001:BEEF:0:0:1:0:0001]"},
				},
			},
			wantErrMatch:    errors.T(errors.Unknown),
			wantErrContains: "failed to parse address",
		},
		{
			name: "invalid-client-cert",
			am: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					PublicId:             testPublicId,
					ClientCertificateKey: testClientCertKey,
					ClientCertificate:    TestInvalidPem,
				},
			},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "failed to parse certificate",
		},
		{
			name: "invalid-deref-aliases",
			am: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					PublicId:           testPublicId,
					DereferenceAliases: "invalid",
				},
			},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: `"invalid" is not a valid ldap dereference alias type:`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			values, err := tc.am.convertValueObjects(testCtx)
			if tc.wantErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tc.wantErrMatch, err), "wanted err %q and got: %+v", tc.wantErrMatch.Code, err)
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			testSortConverted(t, tc.wantValues)
			testSortConverted(t, values)
			assert.Equal(tc.wantValues, values)
		})
	}
	t.Run("missing-public-id", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		wantErrMatch := errors.T(errors.InvalidPublicId)
		am := &AuthMethod{
			AuthMethod: &store.AuthMethod{
				Certificates:         testCerts,
				Urls:                 testLdapServers,
				UserDn:               "user-dn",
				UserAttr:             "user-attr",
				GroupDn:              "group-dn",
				GroupAttr:            "group-attr",
				ClientCertificateKey: testClientCertKey,
				ClientCertificate:    testClientCertEncoded,
				BindDn:               "bind-dn",
				BindPassword:         "bind-password",
				AccountAttributeMaps: testAttrMaps,
			},
		}
		convertedCerts, err := am.convertCertificates(testCtx)
		require.Error(err)
		assert.Nil(convertedCerts)
		assert.Truef(errors.Match(wantErrMatch, err), "wanted err %q and got: %+v", wantErrMatch.Code, err)

		convertedUrls, err := am.convertUrls(testCtx)
		require.Error(err)
		assert.Nil(convertedUrls)
		assert.Truef(errors.Match(wantErrMatch, err), "wanted err %q and got: %+v", wantErrMatch.Code, err)

		convertedMaps, err := am.convertAccountAttributeMaps(testCtx)
		require.Error(err)
		assert.Nil(convertedMaps)
		assert.Truef(errors.Match(wantErrMatch, err), "wanted err %q and got: %+v", wantErrMatch.Code, err)

		convertedUserSearchConf, err := am.convertUserEntrySearchConf(testCtx)
		require.Error(err)
		assert.Nil(convertedUserSearchConf)
		assert.Truef(errors.Match(wantErrMatch, err), "wanted err %q and got: %+v", wantErrMatch.Code, err)

		convertedGroupSearchConf, err := am.convertGroupEntrySearchConf(testCtx)
		require.Error(err)
		assert.Nil(convertedGroupSearchConf)
		assert.Truef(errors.Match(wantErrMatch, err), "wanted err %q and got: %+v", wantErrMatch.Code, err)

		convertedClientCertificate, err := am.convertClientCertificate(testCtx)
		require.Error(err)
		assert.Nil(convertedClientCertificate)
		assert.Truef(errors.Match(wantErrMatch, err), "wanted err %q and got: %+v", wantErrMatch.Code, err)

		convertedBindCredential, err := am.convertBindCredential(testCtx)
		require.Error(err)
		assert.Nil(convertedBindCredential)
		assert.Truef(errors.Match(wantErrMatch, err), "wanted err %q and got: %+v", wantErrMatch.Code, err)

		convertedDerefAliases, err := am.convertDerefAliases(testCtx)
		require.Error(err)
		assert.Nil(convertedDerefAliases)
		assert.Truef(errors.Match(wantErrMatch, err), "wanted err %q and got: %+v", wantErrMatch.Code, err)
	})
}

type converted []any

func (a converted) Len() int      { return len(a) }
func (a converted) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a converted) Less(i, j int) bool {
	switch a[i].(type) {
	case *Url:
		return a[i].(*Url).GetServerUrl() < a[j].(*Url).GetServerUrl()
	case *Certificate:
		return a[i].(*Certificate).GetCert() < a[j].(*Certificate).GetCert()
	}
	return false
}

func testSortConverted(t *testing.T, c *convertedValues) {
	t.Helper()
	sort.Sort(sortableUrls(c.Urls))
	sort.Sort(sortableCerts(c.Certs))
}

type sortableUrls []*Url

func (u sortableUrls) Len() int      { return len(u) }
func (u sortableUrls) Swap(i, j int) { u[i], u[j] = u[j], u[i] }
func (u sortableUrls) Less(i, j int) bool {
	return u[i].GetServerUrl() < u[j].GetServerUrl()
}

type sortableCerts []*Certificate

func (c sortableCerts) Len() int      { return len(c) }
func (c sortableCerts) Swap(i, j int) { c[i], c[j] = c[j], c[i] }
func (c sortableCerts) Less(i, j int) bool {
	return c[i].GetCert() < c[j].GetCert()
}
