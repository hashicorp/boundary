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
	testCert, testCertEncoded := testGenerateCA(t, "localhost")
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
			urls:    TestConvertToUrls(t, "ldaps://alice.com"),
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
				WithGroupAttr(testCtx, "group-attr"),
				WithGroupFilter(testCtx, "group-filter"),
				WithBindCredential(testCtx, "bind-dn", "bind-password"),
				WithCertificates(testCtx, testCert),
				WithClientCertificate(testCtx, derPrivKey, testCert), // not a client cert but good enough for this test.
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
					GroupDn:              "group-dn",
					GroupAttr:            "group-attr",
					GroupFilter:          "group-filter",
					BindDn:               "bind-dn",
					BindPassword:         "bind-password",
					Certificates:         []string{testCertEncoded},
					ClientCertificate:    testCertEncoded,
					ClientCertificateKey: derPrivKey,
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
			name:            "missing-urls",
			ctx:             testCtx,
			scopeId:         "global",
			wantErr:         true,
			wantErrCode:     errors.InvalidParameter,
			wantErrContains: "missing urls",
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
			name:            "opt-error",
			ctx:             testCtx,
			scopeId:         "global",
			urls:            TestConvertToUrls(t, "ldaps://alice.com"),
			opts:            []Option{WithBindCredential(testCtx, "dn", "")},
			wantErr:         true,
			wantErrCode:     errors.InvalidParameter,
			wantErrContains: "ldap.WithBindCredential: missing password",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			am, err := NewAuthMethod(tc.ctx, tc.scopeId, tc.urls, tc.opts...)
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
		testCert, _ := testGenerateCA(t, "localhost")
		_, testPrivKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(err)
		derPrivKey, err := x509.MarshalPKCS8PrivateKey(testPrivKey)
		require.NoError(err)
		am, err := NewAuthMethod(
			testCtx,
			"global",
			TestConvertToUrls(t, "ldaps://alice.com"),
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
		)
		require.NoError(err)
		cp := am.clone()
		assert.True(proto.Equal(cp.AuthMethod, am.AuthMethod))
	})
	t.Run("not-equal", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		am, err := NewAuthMethod(testCtx, "global", TestConvertToUrls(t, "ldaps://alice.com"))
		require.NoError(err)
		am2, err := NewAuthMethod(testCtx, "global", TestConvertToUrls(t, "ldaps://bob.com"))
		require.NoError(err)

		cp := am.clone()
		assert.True(!proto.Equal(cp.AuthMethod, am2.AuthMethod))
	})
}

func TestAuthMethod_oplog(t *testing.T) {
	t.Parallel()
	t.Run("create", func(t *testing.T) {
		am := AllocAuthMethod()
		am.PublicId = "global"
		assert.Equal(t, oplog.Metadata{
			"resource-public-id": []string{am.GetPublicId()},
			"resource-type":      []string{"ldap auth method"},
			"op-type":            []string{oplog.OpType_OP_TYPE_CREATE.String()},
			"scope-id":           []string{am.ScopeId},
		}, am.oplog(oplog.OpType_OP_TYPE_CREATE))
	})
	t.Run("update", func(t *testing.T) {
		am := AllocAuthMethod()
		am.PublicId = "global"
		assert.Equal(t, oplog.Metadata{
			"resource-public-id": []string{am.GetPublicId()},
			"resource-type":      []string{"ldap auth method"},
			"op-type":            []string{oplog.OpType_OP_TYPE_UPDATE.String()},
			"scope-id":           []string{am.ScopeId},
		}, am.oplog(oplog.OpType_OP_TYPE_UPDATE))
	})
}

func Test_convertValueObjects(t *testing.T) {
	testCtx := context.TODO()
	testPublicId := "test-id"
	testLdapServers := []string{"ldaps://ldap1.alice.com", "ldaps://ldap2.alice.com"}
	_, pem := testGenerateCA(t, "localhost")
	testCerts := []string{pem}
	c, err := NewCertificate(testCtx, testPublicId, pem)
	require.NoError(t, err)
	testCertificates := []any{c}

	testUrls := make([]any, 0, len(testLdapServers))
	for priority, uu := range TestConvertToUrls(t, testLdapServers...) {
		u, err := NewUrl(testCtx, testPublicId, priority+1, uu)
		require.NoError(t, err)
		testUrls = append(testUrls, u)
	}

	testUserSearchConf, err := NewUserEntrySearchConf(testCtx, testPublicId, WithUserDn(testCtx, "user-dn"), WithUserAttr(testCtx, "user-attr"))
	require.NoError(t, err)

	testGroupSearchConf, err := NewGroupEntrySearchConf(testCtx, testPublicId, WithGroupDn(testCtx, "group-dn"), WithGroupAttr(testCtx, "group-attr"))
	require.NoError(t, err)

	_, testClientCertEncoded := testGenerateCA(t, "client-cert-host")
	_, testPrivKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	testClientCertKey, err := x509.MarshalPKCS8PrivateKey(testPrivKey)
	require.NoError(t, err)

	testClientCertificate, err := NewClientCertificate(testCtx, testPublicId, testClientCertKey, testClientCertEncoded)
	require.NoError(t, err)

	testBindCredential, err := NewBindCredential(testCtx, testPublicId, "bind-dn", []byte("bind-password"))
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
				},
			},
			wantValues: &convertedValues{
				Certs:                testCertificates,
				Urls:                 testUrls,
				UserEntrySearchConf:  testUserSearchConf,
				GroupEntrySearchConf: testGroupSearchConf,
				ClientCertificate:    testClientCertificate,
				BindCredential:       testBindCredential,
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
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			convertedCerts, err := tc.am.convertCertificates(testCtx)
			if tc.wantErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tc.wantErrMatch, err), "wanted err %q and got: %+v", tc.wantErrMatch.Code, err)
			} else {
				require.NoError(err)
				assert.Equal(tc.wantValues.Certs, convertedCerts)
			}

			convertedUrls, err := tc.am.convertUrls(testCtx)
			if tc.wantErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tc.wantErrMatch, err), "wanted err %q and got: %+v", tc.wantErrMatch.Code, err)
			} else {
				require.NoError(err)
				assert.Equal(tc.wantValues.Urls, convertedUrls)
			}

			convertedUserSearchConf, err := tc.am.convertUserEntrySearchConf(testCtx)
			if tc.wantErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tc.wantErrMatch, err), "wanted err %q and got: %+v", tc.wantErrMatch.Code, err)
			} else {
				require.NoError(err)
				assert.Equal(tc.wantValues.UserEntrySearchConf, convertedUserSearchConf)
			}

			convertedGroupSearchConf, err := tc.am.convertGroupEntrySearchConf(testCtx)
			if tc.wantErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tc.wantErrMatch, err), "wanted err %q and got: %+v", tc.wantErrMatch.Code, err)
			} else {
				require.NoError(err)
				assert.Equal(tc.wantValues.GroupEntrySearchConf, convertedGroupSearchConf)
			}

			convertedClientCertificate, err := tc.am.convertClientCertificate(testCtx)
			if tc.wantErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tc.wantErrMatch, err), "wanted err %q and got: %+v", tc.wantErrMatch.Code, err)
			} else {
				require.NoError(err)
				assert.Equal(tc.wantValues.ClientCertificate, convertedClientCertificate)
			}

			convertedBindCredential, err := tc.am.convertBindCredential(testCtx)
			if tc.wantErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tc.wantErrMatch, err), "wanted err %q and got: %+v", tc.wantErrMatch.Code, err)
			} else {
				require.NoError(err)
				assert.Equal(tc.wantValues.BindCredential, convertedBindCredential)
			}

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
	sort.Sort(converted(c.Urls))
	sort.Sort(converted(c.Certs))
}
