// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oidc

import (
	"context"
	"sort"
	"testing"

	"github.com/hashicorp/boundary/internal/auth/oidc/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	aead "github.com/hashicorp/go-kms-wrapping/v2/aead"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestAuthMethod_Create(t *testing.T) {
	t.Parallel()
	ctx := context.TODO()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	rw := db.New(conn)

	databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	type args struct {
		scopeId      string
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
		wantNewErr      bool
		wantNewIsErr    errors.Code
		wantCreateErr   bool
		wantCreateIsErr errors.Code
	}{
		{
			name: "valid",
			args: args{
				scopeId:      org.PublicId,
				clientId:     "alice_rp",
				clientSecret: ClientSecret("rp-secret"),
				opt: []Option{
					WithIssuer(TestConvertToUrls(t, "http://alice.com")[0]),
					WithApiUrl(TestConvertToUrls(t, "https://api.com")[0]),
					WithDescription("alice's restaurant rp"),
					WithName("alice.com"),
					WithMaxAge(-1),
				},
			},
			create: true,
			want: func() *AuthMethod {
				a := AllocAuthMethod()
				a.ScopeId = org.PublicId
				a.OperationalState = string(InactiveState)
				a.Issuer = "http://alice.com"
				a.ClientId = "alice_rp"
				a.ClientSecret = "rp-secret"
				a.MaxAge = -1
				a.Name = "alice.com"
				a.Description = "alice's restaurant rp"
				a.ApiUrl = "https://api.com"
				return &a
			}(),
		},
		{
			name: "valid with operational state set active",
			args: args{
				scopeId:      org.PublicId,
				clientId:     "alice_rp2",
				clientSecret: ClientSecret("rp-secret2"),
				opt: []Option{
					WithIssuer(TestConvertToUrls(t, "http://alice.com")[0]),
					WithApiUrl(TestConvertToUrls(t, "https://api.com")[0]),
					WithDescription("alice's restaurant rp"),
					WithName("alice2.com"),
					WithMaxAge(-1),
					WithOperationalState(ActivePublicState),
					WithSigningAlgs(EdDSA),
				},
			},
			want: func() *AuthMethod {
				a := AllocAuthMethod()
				a.ScopeId = org.PublicId
				a.OperationalState = string(ActivePublicState)
				a.Issuer = "http://alice.com"
				a.ClientId = "alice_rp2"
				a.ClientSecret = "rp-secret2"
				a.MaxAge = -1
				a.Name = "alice2.com"
				a.Description = "alice's restaurant rp"
				a.ApiUrl = "https://api.com"
				a.SigningAlgs = []string{string(EdDSA)}
				return &a
			}(),
		},
		{
			name: "incomplete with operational state set active",
			args: args{
				scopeId:      org.PublicId,
				clientId:     "alice_rp3",
				clientSecret: ClientSecret("rp-secret3"),
				opt: []Option{
					WithIssuer(TestConvertToUrls(t, "http://alice.com")[0]),
					WithApiUrl(TestConvertToUrls(t, "https://api.com")[0]),
					WithDescription("alice's restaurant rp"),
					WithName("alice3.com"),
					WithMaxAge(-1),
					WithOperationalState(ActivePublicState),
				},
			},
			wantNewErr:   true,
			wantNewIsErr: errors.InvalidParameter,
		},
		{
			name: "dup", // must follow "valid" test. combination of ScopeId, Issuer and ClientId must be unique.
			args: args{
				scopeId:      org.PublicId,
				clientId:     "alice_rp",
				clientSecret: ClientSecret("rp-secret"),
				opt:          []Option{WithIssuer(TestConvertToUrls(t, "http://alice.com")[0]), WithApiUrl(TestConvertToUrls(t, "https://api.com")[0]), WithDescription("alice's restaurant rp"), WithName("alice.com"), WithMaxAge(-1)},
			},
			create: true,
			want: func() *AuthMethod {
				a := AllocAuthMethod()
				a.ScopeId = org.PublicId
				a.OperationalState = string(InactiveState)
				a.Issuer = "http://alice.com"
				a.ClientId = "alice_rp"
				a.ClientSecret = "rp-secret"
				a.MaxAge = -1
				a.Name = "alice.com"
				a.Description = "alice's restaurant rp"
				a.ApiUrl = "https://api.com"
				return &a
			}(),
			wantCreateErr:   true,
			wantCreateIsErr: errors.NotUnique,
		},
		{
			name: "valid-with-no-options",
			args: args{
				scopeId:      org.PublicId,
				clientId:     "eve_rp",
				clientSecret: ClientSecret("rp-secret"),
			},
			want: func() *AuthMethod {
				a := AllocAuthMethod()
				a.ScopeId = org.PublicId
				a.OperationalState = string(InactiveState)
				a.ClientId = "eve_rp"
				a.ClientSecret = "rp-secret"
				return &a
			}(),
		},
		{
			name: "empty-scope-id",
			args: args{
				scopeId:      "",
				clientId:     "alice_rp",
				clientSecret: ClientSecret("rp-secret"),
				opt:          []Option{WithIssuer(TestConvertToUrls(t, "https://alice.com")[0]), WithDescription("alice's restaurant rp"), WithName("alice.com")},
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "nil-issuer", // should succeed.
			args: args{
				scopeId:      org.PublicId,
				clientId:     "alice_rp",
				clientSecret: ClientSecret("rp-secret"),
				opt:          []Option{WithApiUrl(TestConvertToUrls(t, "https://api.com")[0])},
			},
			create: true,
			want: func() *AuthMethod {
				a := AllocAuthMethod()
				a.ScopeId = org.PublicId
				a.OperationalState = string(InactiveState)
				a.Issuer = ""
				a.ClientId = "alice_rp"
				a.ClientSecret = "rp-secret"
				a.MaxAge = 0
				a.ApiUrl = "https://api.com"
				return &a
			}(),
		},
		{
			name: "missing-client-id", // should succeed.
			args: args{
				scopeId:      org.PublicId,
				clientId:     "",
				clientSecret: ClientSecret("rp-secret"),
				opt:          []Option{WithApiUrl(TestConvertToUrls(t, "https://api.com")[0]), WithIssuer(TestConvertToUrls(t, "http://alice.com")[0])},
			},
			want: func() *AuthMethod {
				a := AllocAuthMethod()
				a.ScopeId = org.PublicId
				a.OperationalState = string(InactiveState)
				a.Issuer = "http://alice.com"
				a.ClientId = ""
				a.ClientSecret = "rp-secret"
				a.MaxAge = 0
				a.ApiUrl = "https://api.com"
				return &a
			}(),
		},
		{
			name: "missing-client-secret", // should succeed
			args: args{
				scopeId:      org.PublicId,
				clientId:     "alice_rp",
				clientSecret: ClientSecret(""),
				opt:          []Option{WithApiUrl(TestConvertToUrls(t, "https://api.com")[0]), WithIssuer(TestConvertToUrls(t, "http://alice.com")[0])},
			},
			want: func() *AuthMethod {
				a := AllocAuthMethod()
				a.ScopeId = org.PublicId
				a.OperationalState = string(InactiveState)
				a.Issuer = "http://alice.com"
				a.ClientId = "alice_rp"
				a.ClientSecret = ""
				a.MaxAge = 0
				a.ApiUrl = "https://api.com"
				return &a
			}(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewAuthMethod(ctx, tt.args.scopeId, tt.args.clientId, tt.args.clientSecret, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.True(errors.Match(errors.T(tt.wantIsErr), err))
				return
			}
			if tt.wantNewErr {
				assert.Error(err)
				assert.True(errors.Match(errors.T(tt.wantNewIsErr), err))
				return
			}
			require.NoError(err)
			assert.Equal(tt.want, got)
			if tt.create {
				ctx := context.Background()
				id, err := newAuthMethodId(ctx)
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
	ctx := context.TODO()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	rw := db.New(conn)

	databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	testResource := func(issuer string, clientId, clientSecret string) *AuthMethod {
		got, err := NewAuthMethod(ctx, org.PublicId, clientId, ClientSecret(clientSecret),
			WithIssuer(TestConvertToUrls(t, issuer)[0]), WithApiUrl(TestConvertToUrls(t, "http://api.com")[0]))
		require.NoError(t, err)
		id, err := newAuthMethodId(ctx)
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
		m := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, "alice_rp", "my-dogs-name",
			WithIssuer(TestConvertToUrls(t, "https://alice.com")[0]), WithApiUrl(TestConvertToUrls(t, "https://alice.com")[0]))
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
		m := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, "alice_rp", "my-dogs-name",
			WithIssuer(TestConvertToUrls(t, "https://alice.com")[0]), WithApiUrl(TestConvertToUrls(t, "https://api.com")[0]))
		m2 := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, "alice_rp2", "my-dogs-name",
			WithIssuer(TestConvertToUrls(t, "https://alice.com")[0]), WithApiUrl(TestConvertToUrls(t, "https://api.com")[0]))

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
	m := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, "alice_rp", "my-dogs-name",
		WithIssuer(TestConvertToUrls(t, "https://alice.com")[0]), WithApiUrl(TestConvertToUrls(t, "https://api.com")[0]))

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
	ctx := context.TODO()
	testPublicId := "test-id"

	testAlgs := []string{string(RS256), string(RS384)}
	var testSigningAlgs []*SigningAlg
	for _, a := range []Alg{RS256, RS384} {
		obj, err := NewSigningAlg(ctx, testPublicId, Alg(a))
		require.NoError(t, err)
		testSigningAlgs = append(testSigningAlgs, obj)
	}

	testAuds := []string{"alice", "eve"}
	var testAudiences []*AudClaim
	for _, a := range testAuds {
		obj, err := NewAudClaim(ctx, testPublicId, a)
		require.NoError(t, err)
		testAudiences = append(testAudiences, obj)
	}

	_, pem := testGenerateCA(t, "localhost")
	testCerts := []string{pem}
	c, err := NewCertificate(ctx, testPublicId, pem)
	require.NoError(t, err)
	testCertificates := []*Certificate{c}

	testScopes := []string{"profile", "email"}
	testClaimsScopes := make([]*ClaimsScope, 0, len(testScopes))
	for _, s := range testScopes {
		obj, err := NewClaimsScope(ctx, testPublicId, s)
		require.NoError(t, err)
		testClaimsScopes = append(testClaimsScopes, obj)
	}

	testClaimMaps := []string{"oid=sub", "display_name=name"}
	testAccountClaimMaps := make([]*AccountClaimMap, 0, len(testClaimMaps))
	acms, err := ParseAccountClaimMaps(ctx, testClaimMaps...)
	require.NoError(t, err)
	for _, m := range acms {
		toClaim, err := ConvertToAccountToClaim(ctx, m.To)
		require.NoError(t, err)
		obj, err := NewAccountClaimMap(ctx, testPublicId, m.From, toClaim)
		require.NoError(t, err)
		testAccountClaimMaps = append(testAccountClaimMaps, obj)
	}

	testPrompts := []string{"consent", "select_account"}
	testExpectedPrompts := make([]*Prompt, 0, len(testPrompts))
	for _, a := range testPrompts {
		obj, err := NewPrompt(ctx, testPublicId, PromptParam(a))
		require.NoError(t, err)
		testExpectedPrompts = append(testExpectedPrompts, obj)
	}

	tests := []struct {
		name            string
		authMethodId    string
		algs            []string
		auds            []string
		certs           []string
		scopes          []string
		maps            []string
		prompts         []string
		wantValues      *convertedValues
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name:         "success",
			authMethodId: testPublicId,
			algs:         testAlgs,
			auds:         testAuds,
			certs:        testCerts,
			scopes:       testScopes,
			maps:         testClaimMaps,
			prompts:      testPrompts,
			wantValues: &convertedValues{
				Algs:             testSigningAlgs,
				Auds:             testAudiences,
				Certs:            testCertificates,
				ClaimsScopes:     testClaimsScopes,
				AccountClaimMaps: testAccountClaimMaps,
				Prompts:          testExpectedPrompts,
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
					PublicId:         tt.authMethodId,
					SigningAlgs:      tt.algs,
					AudClaims:        tt.auds,
					Certificates:     tt.certs,
					ClaimsScopes:     tt.scopes,
					AccountClaimMaps: tt.maps,
					Prompts:          tt.prompts,
				},
			}

			convertedAlgs, err := am.convertSigningAlgs(ctx)
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "wanted err %q and got: %+v", tt.wantErrMatch.Code, err)
			} else {
				assert.Equal(tt.wantValues.Algs, convertedAlgs)
			}

			convertedAuds, err := am.convertAudClaims(ctx)
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "wanted err %q and got: %+v", tt.wantErrMatch.Code, err)
			} else {
				assert.Equal(tt.wantValues.Auds, convertedAuds)
			}

			convertedCerts, err := am.convertCertificates(ctx)
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "wanted err %q and got: %+v", tt.wantErrMatch.Code, err)
			} else {
				assert.Equal(tt.wantValues.Certs, convertedCerts)
			}

			convertedScopes, err := am.convertClaimsScopes(ctx)
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "wanted err %q and got: %+v", tt.wantErrMatch.Code, err)
			} else {
				assert.Equal(tt.wantValues.ClaimsScopes, convertedScopes)
			}

			convertedMaps, err := am.convertAccountClaimMaps(ctx)
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "wanted err %q and got: %+v", tt.wantErrMatch.Code, err)
			} else {
				want := make([]*AccountClaimMap, 0, len(tt.wantValues.AccountClaimMaps))
				for _, v := range tt.wantValues.AccountClaimMaps {
					want = append(want, v)
				}
				got := make([]*AccountClaimMap, 0, len(convertedMaps))
				for _, v := range convertedMaps {
					got = append(got, v)
				}
				sort.Slice(want, func(a, b int) bool {
					return want[a].ToClaim < want[b].ToClaim
				})
				sort.Slice(got, func(a, b int) bool {
					return got[a].ToClaim < got[b].ToClaim
				})
				assert.Equal(want, got)
			}

			convertedPrompts, err := am.convertPrompts(ctx)
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "wanted err %q and got: %+v", tt.wantErrMatch.Code, err)
			} else {
				assert.Equal(tt.wantValues.Prompts, convertedPrompts)
			}

			values, err := am.convertValueObjects(ctx)
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "wanted err %q and got: %+v", tt.wantErrMatch.Code, err)
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}
				return
			}
			require.NoError(err)
			testSortConverted(t, tt.wantValues)
			testSortConverted(t, values)
			assert.Equal(tt.wantValues, values)
		})
	}
}

type sortableAlgs []*SigningAlg

func (s sortableAlgs) Len() int      { return len(s) }
func (s sortableAlgs) Swap(i, j int) { s[i], s[j] = s[j], s[i] }
func (s sortableAlgs) Less(i, j int) bool {
	return s[i].GetAlg() < s[j].GetAlg()
}

type sortableCerts []*Certificate

func (s sortableCerts) Len() int      { return len(s) }
func (s sortableCerts) Swap(i, j int) { s[i], s[j] = s[j], s[i] }
func (s sortableCerts) Less(i, j int) bool {
	return s[i].GetCert() < s[j].GetCert()
}

type sortableAccountClaimMaps []*AccountClaimMap

func (s sortableAccountClaimMaps) Len() int      { return len(s) }
func (s sortableAccountClaimMaps) Swap(i, j int) { s[i], s[j] = s[j], s[i] }
func (s sortableAccountClaimMaps) Less(i, j int) bool {
	return s[i].GetFromClaim()+s[i].GetToClaim() < s[j].GetFromClaim()+s[j].GetToClaim()
}

type sortableAuds []*AudClaim

func (s sortableAuds) Len() int      { return len(s) }
func (s sortableAuds) Swap(i, j int) { s[i], s[j] = s[j], s[i] }
func (s sortableAuds) Less(i, j int) bool {
	return s[i].GetAud() < s[j].GetAud()
}

type sortableClaimsScopes []*ClaimsScope

func (s sortableClaimsScopes) Len() int      { return len(s) }
func (s sortableClaimsScopes) Swap(i, j int) { s[i], s[j] = s[j], s[i] }
func (s sortableClaimsScopes) Less(i, j int) bool {
	return s[i].GetScope() < s[j].GetScope()
}

func testSortConverted(t *testing.T, c *convertedValues) {
	t.Helper()
	sort.Sort(sortableAlgs(c.Algs))
	sort.Sort(sortableCerts(c.Certs))
	sort.Sort(sortableAccountClaimMaps(c.AccountClaimMaps))
	sort.Sort(sortableAuds(c.Auds))
	sort.Sort(sortableClaimsScopes(c.ClaimsScopes))
}
