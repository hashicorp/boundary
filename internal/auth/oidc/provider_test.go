// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oidc

import (
	"context"
	"fmt"
	"net/url"
	"testing"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/cap/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_ProviderCaching(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tp := oidc.StartTestProvider(t)
	issuer, err := url.Parse(tp.Addr())
	require.NoError(t, err)

	_, _, signingAlg, _ := tp.SigningKeys()
	allowedRedirect := "https://alice.com/callback"
	authMethodId, err := newAuthMethodId(ctx)
	require.NoError(t, err)
	id := authMethodId
	secret := authMethodId
	p1 := testProvider(t, id, secret, fmt.Sprintf(CallbackEndpoint, allowedRedirect), tp) // provider needs the complete callback URL

	testAm, err := NewAuthMethod(ctx, "fake-org", id, ClientSecret(secret),
		WithIssuer(issuer), WithApiUrl(TestConvertToUrls(t, allowedRedirect)[0]))
	require.NoError(t, err)

	testAm.PublicId = authMethodId
	testAm.SigningAlgs = []string{string(signingAlg)}
	testAm.ApiUrl = allowedRedirect
	testAm.Certificates = []string{tp.CACert()}

	t.Run("get-equal-providers", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		cache := newProviderCache()
		assert.Equal(0, len(cache.cache))
		cache.set(ctx, authMethodId, p1)
		got, err := cache.get(ctx, testAm)
		require.NoError(err)
		assert.Equal(p1, got)
	})
	t.Run("get-unequal-providers", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		cache := newProviderCache()
		assert.Equal(0, len(cache.cache))
		cache.set(ctx, authMethodId, p1)
		newAm := testAm.Clone()
		newAm.ClientId = "new-client-id"
		got, err := cache.get(ctx, newAm)
		require.NoError(err)
		assert.NotEqual(p1, got)
	})
	t.Run("refetch-from-singleton", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// use the singleton
		cache := providerCache()
		cache.set(ctx, authMethodId, p1)

		// use the singleton via a new var
		cache2 := providerCache()
		got, err := cache2.get(ctx, testAm)
		require.NoError(err)
		assert.Equal(p1, got)
	})
	t.Run("delete", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// use the singleton
		cache := newProviderCache()
		cache.set(ctx, authMethodId, p1)
		require.Equal(1, len(cache.cache))

		cache.delete(ctx, authMethodId)
		assert.Equal(0, len(cache.cache))
	})
}

func Test_convertToProvider(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tp := oidc.StartTestProvider(t)
	issuer, err := url.Parse(tp.Addr())
	require.NoError(t, err)

	_, _, signingAlg, _ := tp.SigningKeys()
	allowedRedirect := "https://alice.com/callback"

	authMethodId, err := newAuthMethodId(ctx)
	require.NoError(t, err)
	id := authMethodId
	secret := authMethodId
	p := testProvider(t, id, secret, fmt.Sprintf(CallbackEndpoint, allowedRedirect), tp) // provider callback needs the complete URL
	testAm, err := NewAuthMethod(ctx, "fake-org", id, ClientSecret(secret),
		WithIssuer(issuer), WithApiUrl(TestConvertToUrls(t, allowedRedirect)[0]))
	require.NoError(t, err)

	testAm.PublicId = authMethodId
	testAm.SigningAlgs = []string{string(signingAlg)}
	testAm.ApiUrl = allowedRedirect
	testAm.Certificates = []string{tp.CACert()}

	tests := []struct {
		name        string
		am          *AuthMethod
		want        *oidc.Provider
		wantErr     bool
		wantErrCode errors.Code
	}{
		{"equal", testAm, p, false, errors.Unknown},
		{"missing-issuer", func() *AuthMethod { cp := testAm.Clone(); cp.Issuer = ""; return cp }(), nil, true, errors.InvalidParameter},
		{"missing-client-id", func() *AuthMethod { cp := testAm.Clone(); cp.ClientId = ""; return cp }(), nil, true, errors.InvalidParameter},
		{"missing-client-secret", func() *AuthMethod { cp := testAm.Clone(); cp.ClientSecret = ""; return cp }(), nil, true, errors.InvalidParameter},
		{"missing-algs", func() *AuthMethod { cp := testAm.Clone(); cp.SigningAlgs = nil; return cp }(), nil, true, errors.InvalidParameter},
		{"missing-api-url", func() *AuthMethod { cp := testAm.Clone(); cp.ApiUrl = ""; return cp }(), nil, true, errors.InvalidParameter},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			got, err := convertToProvider(ctx, tt.am)
			if tt.wantErr {
				require.Error(err)
				assert.Truef(errors.Match(errors.T(tt.wantErrCode), err), "%v", err)
				return
			}
			require.NoError(err)
			wantHash, err := tt.want.ConfigHash()
			require.NoError(err)
			gotHash, err := got.ConfigHash()
			require.NoError(err)
			assert.Equal(wantHash, gotHash)
		})
	}
}
