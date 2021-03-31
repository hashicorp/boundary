package oidc

import (
	"context"
	"net/url"
	"testing"

	"github.com/hashicorp/boundary/internal/auth/oidc/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-kms-wrapping/wrappers/aead"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestAuthMethod_Create(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	rw := db.New(conn)

	databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	type args struct {
		scopeId      string
		discoveryURL *url.URL
		clientId     string
		clientSecret ClientSecret
		opt          []Option
	}
	tests := []struct {
		name            string
		args            args
		want            *AuthMethod
		wantErr         bool
		wantIsErr       errors.Code
		create          bool
		wantCreateErr   bool
		wantCreateIsErr errors.Code
	}{
		{
			name: "valid",
			args: args{
				scopeId:      org.PublicId,
				discoveryURL: func() *url.URL { u, err := url.Parse("http://alice.com"); require.NoError(t, err); return u }(),
				clientId:     "alice_rp",
				clientSecret: ClientSecret("rp-secret"),
				opt:          []Option{WithDescription("alice's restaurant rp"), WithName("alice.com"), WithMaxAge(-1)},
			},
			create: true,
			want: func() *AuthMethod {
				a := AllocAuthMethod()
				a.ScopeId = org.PublicId
				a.OperationalState = string(InactiveState)
				a.DiscoveryUrl = "http://alice.com"
				a.ClientId = "alice_rp"
				a.ClientSecret = "rp-secret"
				a.MaxAge = -1
				a.Name = "alice.com"
				a.Description = "alice's restaurant rp"
				return &a
			}(),
		},
		{
			name: "dup", // must follow "valid" test. combination of ScopeId, DiscoveryUrl and ClientId must be unique.
			args: args{
				scopeId:      org.PublicId,
				discoveryURL: func() *url.URL { u, err := url.Parse("http://alice.com"); require.NoError(t, err); return u }(),
				clientId:     "alice_rp",
				clientSecret: ClientSecret("rp-secret"),
				opt:          []Option{WithDescription("alice's restaurant rp"), WithName("alice.com"), WithMaxAge(-1)},
			},
			create: true,
			want: func() *AuthMethod {
				a := AllocAuthMethod()
				a.ScopeId = org.PublicId
				a.OperationalState = string(InactiveState)
				a.DiscoveryUrl = "http://alice.com"
				a.ClientId = "alice_rp"
				a.ClientSecret = "rp-secret"
				a.MaxAge = -1
				a.Name = "alice.com"
				a.Description = "alice's restaurant rp"
				return &a
			}(),
			wantCreateErr:   true,
			wantCreateIsErr: errors.NotUnique,
		},
		{
			name: "valid-with-no-options",
			args: args{
				scopeId:      org.PublicId,
				discoveryURL: func() *url.URL { u, err := url.Parse("http://alice.com"); require.NoError(t, err); return u }(),
				clientId:     "eve_rp",
				clientSecret: ClientSecret("rp-secret"),
			},
			create: true,
			want: func() *AuthMethod {
				a := AllocAuthMethod()
				a.ScopeId = org.PublicId
				a.OperationalState = string(InactiveState)
				a.DiscoveryUrl = "http://alice.com"
				a.ClientId = "eve_rp"
				a.ClientSecret = "rp-secret"
				a.MaxAge = 0
				return &a
			}(),
		},
		{
			name: "empty-scope-id",
			args: args{
				scopeId:      "",
				discoveryURL: func() *url.URL { u, err := url.Parse("http://alice.com"); require.NoError(t, err); return u }(),
				clientId:     "alice_rp",
				clientSecret: ClientSecret("rp-secret"),
				opt:          []Option{WithDescription("alice's restaurant rp"), WithName("alice.com")},
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "nil-url", // should succeed.
			args: args{
				scopeId:      org.PublicId,
				discoveryURL: nil,
				clientId:     "alice_rp",
				clientSecret: ClientSecret("rp-secret"),
			},
			create: true,
			want: func() *AuthMethod {
				a := AllocAuthMethod()
				a.ScopeId = org.PublicId
				a.OperationalState = string(InactiveState)
				a.DiscoveryUrl = ""
				a.ClientId = "alice_rp"
				a.ClientSecret = "rp-secret"
				a.MaxAge = 0
				return &a
			}(),
		},
		{
			name: "missing-client-id", // should succeed.
			args: args{
				scopeId:      org.PublicId,
				discoveryURL: func() *url.URL { u, err := url.Parse("http://alice.com"); require.NoError(t, err); return u }(),
				clientId:     "",
				clientSecret: ClientSecret("rp-secret"),
			},
			want: func() *AuthMethod {
				a := AllocAuthMethod()
				a.ScopeId = org.PublicId
				a.OperationalState = string(InactiveState)
				a.DiscoveryUrl = "http://alice.com"
				a.ClientId = ""
				a.ClientSecret = "rp-secret"
				a.MaxAge = 0
				return &a
			}(),
		},
		{
			name: "missing-client-secret", // should succeed
			args: args{
				scopeId:      org.PublicId,
				discoveryURL: func() *url.URL { u, err := url.Parse("http://alice.com"); require.NoError(t, err); return u }(),
				clientId:     "alice_rp",
				clientSecret: ClientSecret(""),
			},
			want: func() *AuthMethod {
				a := AllocAuthMethod()
				a.ScopeId = org.PublicId
				a.OperationalState = string(InactiveState)
				a.DiscoveryUrl = "http://alice.com"
				a.ClientId = "alice_rp"
				a.ClientSecret = ""
				a.MaxAge = 0
				return &a
			}(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewAuthMethod(tt.args.scopeId, tt.args.discoveryURL, tt.args.clientId, tt.args.clientSecret, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.True(errors.Match(errors.T(tt.wantIsErr), err))
				return
			}
			require.NoError(err)
			assert.Equal(tt.want, got)
			if tt.create {
				ctx := context.Background()
				id, err := newAuthMethodId()
				require.NoError(err)
				got.PublicId = id
				err = got.encrypt(ctx, databaseWrapper)
				require.NoError(err)
				err = rw.Create(ctx, got)
				if tt.wantCreateErr {
					assert.Error(err)
					assert.True(errors.Match(errors.T(tt.wantCreateIsErr), err))
					return
				} else {
					assert.NoError(err)
				}

				found := AllocAuthMethod()
				found.PublicId = got.PublicId
				require.NoError(rw.LookupByPublicId(ctx, &found))
				require.NoError(found.decrypt(ctx, databaseWrapper))
				assert.Equal(got, &found)
			}
		})
	}
}

func TestAuthMethod_Delete(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	rw := db.New(conn)
	ctx := context.Background()

	databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	testResource := func(discoveryUrl string, clientId, clientSecret string) *AuthMethod {
		got, err := NewAuthMethod(org.PublicId, TestConvertToUrls(t, discoveryUrl)[0], clientId, ClientSecret(clientSecret))
		require.NoError(t, err)
		id, err := newAuthMethodId()
		require.NoError(t, err)
		got.PublicId = id
		err = got.encrypt(ctx, databaseWrapper)
		require.NoError(t, err)
		return got
	}
	tests := []struct {
		name            string
		authMethod      *AuthMethod
		overrides       func(*AuthMethod)
		wantRowsDeleted int
		wantErr         bool
		wantErrMsg      string
	}{
		{
			name:            "valid",
			authMethod:      testResource("https://alice.com", "alice-rp", "alice's dog's name"),
			wantErr:         false,
			wantRowsDeleted: 1,
		},
		{
			name:            "bad-id",
			authMethod:      testResource("https://alice.com", "alice-rp", "alice's dog's name"),
			overrides:       func(a *AuthMethod) { a.PublicId = "bad-id" },
			wantErr:         false,
			wantRowsDeleted: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			ctx := context.Background()
			cp := tt.authMethod.Clone()
			require.NoError(rw.Create(ctx, &cp))

			if tt.overrides != nil {
				tt.overrides(cp)
			}
			deletedRows, err := rw.Delete(context.Background(), &cp)
			if tt.wantErr {
				require.Error(err)
				return
			}
			require.NoError(err)
			if tt.wantRowsDeleted == 0 {
				assert.Equal(tt.wantRowsDeleted, deletedRows)
				return
			}
			assert.Equal(tt.wantRowsDeleted, deletedRows)
			foundAuthMethod := AllocAuthMethod()
			foundAuthMethod.PublicId = tt.authMethod.PublicId
			err = rw.LookupById(context.Background(), &foundAuthMethod)
			require.Error(err)
			assert.True(errors.IsNotFoundError(err))
		})
	}
}

func TestAuthMethod_Clone(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)

	t.Run("valid", func(t *testing.T) {
		assert := assert.New(t)
		org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
		require.NoError(t, err)
		m := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, TestConvertToUrls(t, "https://alice.com")[0], "alice_rp", "my-dogs-name")
		m.DisableDiscoveredConfigValidation = true

		cp := m.Clone()
		assert.Equal(cp.DisableDiscoveredConfigValidation, true)
		assert.True(proto.Equal(cp.AuthMethod, m.AuthMethod))
	})
	t.Run("not-equal", func(t *testing.T) {
		assert := assert.New(t)
		org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
		require.NoError(t, err)
		m := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, TestConvertToUrls(t, "https://alice.com")[0], "alice_rp", "my-dogs-name")
		m2 := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, TestConvertToUrls(t, "https://alice.com")[0], "alice_rp2", "my-dogs-name")

		cp := m.Clone()
		assert.True(!proto.Equal(cp.AuthMethod, m2.AuthMethod))
	})
}

func TestAuthMethod_SetTableName(t *testing.T) {
	t.Parallel()
	defaultTableName := defaultAuthMethodTableName
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

func Test_encrypt_decrypt_hmac(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rootWrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, rootWrapper)
	org, proj := iam.TestScopes(t, iam.TestRepo(t, conn, rootWrapper))
	databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	projDatabaseWrapper, err := kmsCache.GetWrapper(ctx, proj.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	m := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, TestConvertToUrls(t, "https://alice.com")[0], "alice_rp", "my-dogs-name")

	tests := []struct {
		name                string
		am                  *AuthMethod
		hmacWrapper         wrapping.Wrapper
		wantHmacErrMatch    *errors.Template
		encryptWrapper      wrapping.Wrapper
		wantEncryptErrMatch *errors.Template
		decryptWrapper      wrapping.Wrapper
		wantDecryptErrMatch *errors.Template
	}{
		{
			name:           "success",
			am:             m,
			hmacWrapper:    databaseWrapper,
			encryptWrapper: databaseWrapper,
			decryptWrapper: databaseWrapper,
		},
		{
			name:                "encrypt-missing-wrapper",
			am:                  m,
			hmacWrapper:         databaseWrapper,
			wantEncryptErrMatch: errors.T(errors.InvalidParameter),
		},
		{
			name:                "encrypt-bad-wrapper",
			am:                  m,
			hmacWrapper:         databaseWrapper,
			encryptWrapper:      &aead.Wrapper{},
			wantEncryptErrMatch: errors.T(errors.Encrypt),
		},
		{
			name:                "encrypt-missing-wrapper",
			am:                  m,
			hmacWrapper:         databaseWrapper,
			encryptWrapper:      databaseWrapper,
			wantDecryptErrMatch: errors.T(errors.InvalidParameter),
		},
		{
			name:                "decrypt-bad-wrapper",
			am:                  m,
			hmacWrapper:         databaseWrapper,
			encryptWrapper:      databaseWrapper,
			decryptWrapper:      &aead.Wrapper{},
			wantDecryptErrMatch: errors.T(errors.Decrypt),
		},
		{
			name:                "decrypt-wrong-wrapper",
			am:                  m,
			hmacWrapper:         databaseWrapper,
			encryptWrapper:      databaseWrapper,
			decryptWrapper:      projDatabaseWrapper,
			wantDecryptErrMatch: errors.T(errors.Decrypt),
		},
		{
			name:             "hmac-missing-wrapper",
			am:               m,
			encryptWrapper:   databaseWrapper,
			decryptWrapper:   databaseWrapper,
			wantHmacErrMatch: errors.T(errors.InvalidParameter),
		},
		{
			name:             "hmac-bad-wrapper",
			am:               m,
			hmacWrapper:      &aead.Wrapper{},
			encryptWrapper:   databaseWrapper,
			decryptWrapper:   databaseWrapper,
			wantHmacErrMatch: errors.T(errors.InvalidParameter),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			hmacAuthMethod := tt.am.Clone()
			err = hmacAuthMethod.hmacClientSecret(ctx, tt.hmacWrapper)
			if tt.wantHmacErrMatch != nil {
				require.Error(err)
			} else {
				require.NoError(err)
			}

			encryptedAuthMethod := tt.am.Clone()
			err = encryptedAuthMethod.encrypt(ctx, tt.encryptWrapper)
			if tt.wantEncryptErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tt.wantEncryptErrMatch, err), "expected %q and got err: %+v", tt.wantEncryptErrMatch.Code, err)
				return
			}
			require.NoError(err)
			assert.NotEmpty(encryptedAuthMethod.CtClientSecret)
			assert.NotEmpty(encryptedAuthMethod.ClientSecretHmac)

			decryptedAuthMethod := encryptedAuthMethod.Clone()
			decryptedAuthMethod.ClientSecret = ""
			err = decryptedAuthMethod.decrypt(ctx, tt.decryptWrapper)
			if tt.wantDecryptErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tt.wantDecryptErrMatch, err), "expected %q and got err: %+v", tt.wantDecryptErrMatch.Code, err)
				return
			}
			require.NoError(err)
			assert.Equal(tt.am.ClientSecret, decryptedAuthMethod.ClientSecret)
		})
	}
}

func Test_convertValueObjects(t *testing.T) {
	testPublicId := "test-id"

	testAlgs := []string{string(RS256), string(RS384)}
	var testSigningAlgs []interface{}
	for _, a := range []Alg{RS256, RS384} {
		obj, err := NewSigningAlg(testPublicId, Alg(a))
		require.NoError(t, err)
		testSigningAlgs = append(testSigningAlgs, obj)
	}

	testAuds := []string{"alice", "eve"}
	var testAudiences []interface{}
	for _, a := range testAuds {
		obj, err := NewAudClaim(testPublicId, a)
		require.NoError(t, err)
		testAudiences = append(testAudiences, obj)
	}

	testCbs := []string{"https://alice.com/callback", "https://localhost/callback"}
	var testCallbacks []interface{}
	for _, cb := range testCbs {
		obj, err := NewCallbackUrl(testPublicId, TestConvertToUrls(t, cb)[0])
		require.NoError(t, err)
		testCallbacks = append(testCallbacks, obj)
	}

	_, pem := testGenerateCA(t, "localhost")
	testCerts := []string{pem}
	c, err := NewCertificate(testPublicId, pem)
	require.NoError(t, err)
	testCertificates := []interface{}{c}

	tests := []struct {
		name            string
		authMethodId    string
		algs            []string
		auds            []string
		callbacks       []string
		certs           []string
		wantValues      *convertedValues
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name:         "success",
			authMethodId: testPublicId,
			algs:         testAlgs,
			auds:         testAuds,
			callbacks:    testCbs,
			certs:        testCerts,
			wantValues: &convertedValues{
				Algs:      testSigningAlgs,
				Callbacks: testCallbacks,
				Auds:      testAudiences,
				Certs:     testCertificates,
			},
		},
		{
			name:         "missing-public-id",
			algs:         testAlgs,
			wantErrMatch: errors.T(errors.InvalidPublicId),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			am := &AuthMethod{
				AuthMethod: &store.AuthMethod{
					PublicId:     tt.authMethodId,
					SigningAlgs:  tt.algs,
					AudClaims:    tt.auds,
					CallbackUrls: tt.callbacks,
					Certificates: tt.certs,
				},
			}

			convertedAlgs, err := am.convertSigningAlgs()
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "wanted err %q and got: %+v", tt.wantErrMatch.Code, err)
			} else {
				assert.Equal(tt.wantValues.Algs, convertedAlgs)
			}

			convertedAuds, err := am.convertAudClaims()
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "wanted err %q and got: %+v", tt.wantErrMatch.Code, err)
			} else {
				assert.Equal(tt.wantValues.Auds, convertedAuds)
			}

			convertedCallbacks, err := am.convertCallbacks()
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "wanted err %q and got: %+v", tt.wantErrMatch.Code, err)
			} else {
				assert.Equal(tt.wantValues.Callbacks, convertedCallbacks)
			}

			convertedCerts, err := am.convertCertificates()
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "wanted err %q and got: %+v", tt.wantErrMatch.Code, err)
			} else {
				assert.Equal(tt.wantValues.Certs, convertedCerts)
			}

			values, err := am.convertValueObjects()
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "wanted err %q and got: %+v", tt.wantErrMatch.Code, err)
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantValues, values)
		})
	}
}
