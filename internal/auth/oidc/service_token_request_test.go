package oidc

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_TokenRequest(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	rootWrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, rootWrapper)

	iamRepo := iam.TestRepo(t, conn, rootWrapper)
	org, _ := iam.TestScopes(t, iamRepo)
	orgDatabaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	atRepoFn := func() (*authtoken.Repository, error) {
		r, err := authtoken.NewRepository(rw, rw, kmsCache)
		require.NoError(t, err)
		return r, nil
	}
	testAtRepo, err := authtoken.NewRepository(rw, rw, kmsCache)
	require.NoError(t, err)

	// a reusable test authmethod for the unit tests
	testAuthMethod := TestAuthMethod(t, conn, orgDatabaseWrapper, org.PublicId, ActivePublicState,
		TestConvertToUrls(t, "https://alice.com")[0],
		"alice-rp", "fido",
		WithSigningAlgs(Alg(RS256)),
		WithCallbackUrls(TestConvertToUrls(t, "https://alice.com/callback")[0]))

	testAcct := TestAccount(t, conn, testAuthMethod.PublicId, TestConvertToUrls(t, "https://alice.com")[0], "alice")
	testUser := iam.TestUser(t, iamRepo, org.PublicId, iam.WithAccountIds(testAcct.PublicId))

	tests := []struct {
		name         string
		kms          *kms.Kms
		atRepoFn     AuthTokenRepoFactory
		tokenRequest string
		wantErrMatch *errors.Template
	}{
		{
			name:     "success",
			kms:      kmsCache,
			atRepoFn: atRepoFn,
			tokenRequest: func() string {
				tokenPublicId, err := authtoken.NewAuthTokenId()
				require.NoError(t, err)
				testPendingToken(t, testAtRepo, testUser, testAcct, tokenPublicId)
				return testTokenRequestId(t, testAuthMethod, kmsCache, 200*time.Second, tokenPublicId)
			}(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			conn.LogMode(true)
			gotTk, err := TokenRequest(ctx, tt.kms, tt.atRepoFn, tt.tokenRequest)
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "wanted %q and got: %+v", tt.wantErrMatch.Code, err)
				return
			}
			require.NoError(err)
			assert.NotEmpty(gotTk)
		})
	}
}
