package oidc

import (
	"context"
	"crypto/x509"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
)

func TestRewrap_authMethodRewrapFn(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	rw := db.New(conn)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	convertAlg := func(alg ...Alg) []string {
		s := make([]string, 0, len(alg))
		for _, a := range alg {
			s = append(s, string(a))
		}
		return s
	}

	// fetch the current key version
	kmsWrapper, err := kmsCache.GetWrapper(ctx, org.Scope.GetPublicId(), kms.KeyPurposeDatabase)
	assert.NoError(t, err)

	currentKeyVersion, err := kmsWrapper.KeyId(ctx)
	assert.NoError(t, err)

	// perform the setup for the authmethod
	algs := []Alg{RS256, ES256}
	cbs := TestConvertToUrls(t, "https://www.alice.com/callback")[0]
	auds := []string{"alice-rp", "bob-rp"}
	cert1, pem1 := testGenerateCA(t, "localhost")
	cert2, pem2 := testGenerateCA(t, "localhost")
	certs := []*x509.Certificate{cert1, cert2}
	pems := []string{pem1, pem2}
	am, err := NewAuthMethod(
		ctx,
		org.PublicId,
		"alice-rp",
		"alice-secret", WithAudClaims("alice-rp"),
		WithAudClaims(auds...),
		WithIssuer(TestConvertToUrls(t, "https://www.alice.com")[0]),
		WithApiUrl(cbs),
		WithSigningAlgs(algs...),
		WithCertificates(certs...),
		WithName("alice's restaurant"),
		WithDescription("it's a good place to eat"),
		WithClaimsScopes("email", "profile"),
		WithAccountClaimMap(map[string]AccountToClaim{"display_name": ToNameClaim, "oid": ToSubClaim}),
	)
	assert.NoError(t, err)
	assert.Equal(t, am.SigningAlgs, convertAlg(algs...))
	assert.Equal(t, am.ApiUrl, cbs.String())
	assert.Equal(t, "https://www.alice.com", am.Issuer)
	assert.Equal(t, am.AudClaims, auds)
	assert.Equal(t, am.Certificates, pems)
	assert.Equal(t, am.OperationalState, string(InactiveState))

	// CreateAuthMethod to store it, both from oidc repo
	repo, err := NewRepository(ctx, rw, rw, kmsCache)
	assert.NoError(t, err)

	got, err := repo.CreateAuthMethod(ctx, am)
	assert.NoError(t, err)
	assert.NotNil(t, got)

	// double check that we used the expected key version to encrypt the material
	assert.Equal(t, got.KeyId, currentKeyVersion)

	// rotate the keys here so that we have a new key version
	err = kmsCache.RotateKeys(ctx, org.Scope.GetPublicId())
	assert.NoError(t, err)

	// trigger the rewrap func
	err = authMethodRewrapFn(ctx, got.KeyId, rw, rw, kmsCache)
	assert.NoError(t, err)

	// fetch the new key version
	kmsWrapper, err = kmsCache.GetWrapper(ctx, org.Scope.GetPublicId(), kms.KeyPurposeDatabase)
	assert.NoError(t, err)
	newKeyVersion, err := kmsWrapper.KeyId(ctx)
	assert.NoError(t, err)

	// make sure there actually is a new key version
	assert.NotEqual(t, currentKeyVersion, newKeyVersion)

	// fetching the latest auth method itself
	ams, err := repo.getAuthMethods(ctx, got.GetPublicId(), []string{})
	assert.NoError(t, err)
	newAm := ams[0]

	// since getAuthMethods automatically decrypts the secret, all we need to do is make sure
	// that it's correct and that it uses the newest key version id
	assert.Equal(t, newAm.ClientSecret, "alice-secret")
	assert.Equal(t, newAm.KeyId, newKeyVersion)
}
