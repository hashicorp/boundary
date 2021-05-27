package oidc_test

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/auth/oidc/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/servers/controller"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testFakeManagedGroupFilter = `"/foo" == "bar"`

func Test_SetManagedGroupMembers(t *testing.T) {
	t.Parallel()
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	conn := tc.DbConn()
	rw := db.New(conn)

	kmsCache := tc.Kms()
	iamRepo := tc.IamRepo()
	org, _ := iam.TestScopes(t, iamRepo)

	ctx := context.Background()
	databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	authMethod := oidc.TestAuthMethod(
		t, conn, databaseWrapper, org.GetPublicId(), oidc.ActivePrivateState,
		"alice-rp", "fido",
		oidc.WithSigningAlgs(oidc.RS256),
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://www.alice.com")[0]),
		oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)

	repo, err := oidc.NewRepository(rw, rw, kmsCache)
	require.NoError(t, err)
	require.NotNil(t, repo)

	mgIds := make([]string, 0, 10)

	for i := 0; i < 100; i++ {
		mg := oidc.AllocManagedGroup()
		mg.AuthMethodId = authMethod.PublicId
		mg.Filter = testFakeManagedGroupFilter
		got, err := repo.CreateManagedGroup(context.Background(), org.GetPublicId(), mg)
		require.NoError(t, err)
		mgIds = append(mgIds, got.PublicId)
	}

	// Fetch valid OIDC accounts. One will be "static" where we will simply
	// ensure modifying the groups for the other doesn't affect it; the other
	// will be used for testing.
	rows, err := rw.Query(ctx, "select public_id from auth_oidc_account limit 2", nil)
	require.NoError(t, err)
	require.True(t, rows.Next())
	var staticAccountId string
	require.NoError(t, rows.Scan(&staticAccountId))
	require.NotEmpty(t, staticAccountId)
	require.True(t, rows.Next())
	var accountId string
	require.NoError(t, rows.Scan(&accountId))
	require.NotEmpty(t, accountId)

	tests := []struct {
		name string
		// If true, we will auto populate necesary values into the function
		validPrereqs bool

		// Else these can be used for testing
		authMethod        *oidc.AuthMethod
		authMethodId      string
		account           *oidc.Account
		accountId         string
		authMethodScopeId string
		mgs               []*oidc.ManagedGroup

		wantErr         errors.Code
		wantErrContains string
	}{
		{
			name:            "nil auth method",
			wantErr:         errors.InvalidParameter,
			wantErrContains: "missing auth method",
		},
		{
			name:            "missing auth method store",
			authMethod:      &oidc.AuthMethod{},
			wantErr:         errors.InvalidParameter,
			wantErrContains: "missing auth method store",
		},
		{
			name:            "missing auth method id",
			authMethod:      &oidc.AuthMethod{AuthMethod: &store.AuthMethod{}},
			wantErr:         errors.InvalidParameter,
			wantErrContains: "missing auth method id",
		},
		{
			name:            "missing auth method scope id",
			authMethod:      &oidc.AuthMethod{AuthMethod: &store.AuthMethod{PublicId: authMethod.PublicId}},
			wantErr:         errors.InvalidParameter,
			wantErrContains: "missing auth method scope id",
		},
		{
			name:            "missing account",
			authMethod:      authMethod,
			wantErr:         errors.InvalidParameter,
			wantErrContains: "missing account",
		},
		{
			name:            "missing account store",
			authMethod:      authMethod,
			account:         &oidc.Account{},
			wantErr:         errors.InvalidParameter,
			wantErrContains: "missing account store",
		},
		{
			name:            "missing account id",
			authMethod:      authMethod,
			account:         &oidc.Account{Account: &store.Account{}},
			wantErr:         errors.InvalidParameter,
			wantErrContains: "missing account id",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			if tt.validPrereqs {
				tt.authMethod = authMethod
				tt.account = oidc.AllocAccount()
				tt.account.PublicId = accountId
			}
			num, err := repo.SetManagedGroupMembers(ctx, tt.authMethod, tt.account, tt.mgs)
			if tt.wantErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantErr), err), "Unexpected error %s", err)
				if tt.wantErrContains != "" {
					assert.True(strings.Contains(err.Error(), tt.wantErrContains))
				}
				return
			}
			require.NoError(err)
			_ = num

			// assert.NoError(db.TestVerifyOplog(t, rw, got.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second)))
		})
	}
}
