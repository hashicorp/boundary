package oidc_test

import (
	"context"
	"log"
	"math/rand"
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

	mgs := make([]*oidc.ManagedGroup, 0, 10)

	for i := 0; i < 100; i++ {
		mg := oidc.AllocManagedGroup()
		mg.AuthMethodId = authMethod.PublicId
		mg.Filter = testFakeManagedGroupFilter
		got, err := repo.CreateManagedGroup(context.Background(), org.GetPublicId(), mg)
		require.NoError(t, err)
		mgs = append(mgs, got)
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

	account := oidc.AllocAccount()
	account.PublicId = accountId

	tests := []struct {
		name string
		// If true, we will auto populate necesary values into the function
		validPrereqs bool

		// Else these can be used for testing
		authMethod            *oidc.AuthMethod
		authMethodId          string
		account               *oidc.Account
		accountId             string
		authMethodScopeId     string
		wantPreseededMgsCount int
		wantMgsCount          int
		specificMgs           []*oidc.ManagedGroup

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
		{
			name:         "valid fixed",
			validPrereqs: true,
			specificMgs:  mgs[0:20],
		},
		{
			name:         "valid fixed, second test",
			validPrereqs: true,
			specificMgs:  mgs[0:20],
		},
		{
			name:         "valid none",
			validPrereqs: true,
			wantMgsCount: 0,
		},
		{
			name:         "valid none, second test",
			validPrereqs: true,
			wantMgsCount: 0,
		},
		{
			name:         "valid fixed, prep for random",
			validPrereqs: true,
			specificMgs:  mgs[20:40],
		},
		{
			name:         "valid random",
			validPrereqs: true,
			wantMgsCount: 20,
		},
		/*
			{
				name:         "valid random, second test",
				validPrereqs: true,
				wantMgsCount: 20,
			},
				{
					name:         "valid with duplicates",
					validPrereqs: true,
					specificMgs:  append(mgs[0:20], mgs[0:20]...),
				},
		*/
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			// We are intentionally carrying things over between tests to be
			// more realistic but that means we need correct versions, so update
			// them first.
			currMgs, err := repo.ListManagedGroups(ctx, authMethod.PublicId)
			require.NoError(err)
			require.Len(currMgs, 100)
			currVersionMap := make(map[string]uint32, len(currMgs))
			for _, currMg := range currMgs {
				currVersionMap[currMg.PublicId] = currMg.Version
			}
			for _, mg := range mgs {
				if mg.Version != currVersionMap[mg.PublicId] {
					log.Println("updating version", mg.PublicId, mg.Version, "to", currVersionMap[mg.PublicId])
				}
				mg.Version = currVersionMap[mg.PublicId]
			}

			var mgsToTest []*oidc.ManagedGroup
			var finalMgs map[string]*oidc.ManagedGroup
			// If we know the inputs are sane, create the test data
			if tt.validPrereqs {
				tt.authMethod = authMethod
				tt.account = oidc.AllocAccount()
				tt.account.PublicId = accountId
				switch {
				// If we want to select specific IDs, create member accounts and append
				case tt.specificMgs != nil:
					mgsToTest = make([]*oidc.ManagedGroup, len(tt.specificMgs))
					for i, mg := range tt.specificMgs {
						newMg := oidc.AllocManagedGroup()
						newMg.PublicId = mg.PublicId
						newMg.Version = mg.Version
						newMg.AuthMethodId = tt.authMethodId
						mgsToTest[i] = newMg
					}
				default:
					// Otherwise select at random
					mgsToTest = make([]*oidc.ManagedGroup, tt.wantMgsCount)
					for i := 0; i < tt.wantMgsCount; i++ {
						mg := mgs[rand.Int()%len(mgs)]
						newMg := oidc.AllocManagedGroup()
						newMg.PublicId = mg.PublicId
						newMg.Version = mg.Version
						newMg.AuthMethodId = mg.AuthMethodId
						mgsToTest[i] = newMg
					}
				}
				finalMgs = make(map[string]*oidc.ManagedGroup)
				for _, v := range mgsToTest {
					finalMgs[v.PublicId] = v
				}
			}

			t.Log(len(mgsToTest))
			t.Log(len(finalMgs))

			memberships, _, err := repo.SetManagedGroupMemberships(ctx, tt.authMethod, tt.account, mgsToTest)
			if tt.wantErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantErr), err), "Unexpected error %s", err)
				if tt.wantErrContains != "" {
					assert.True(strings.Contains(err.Error(), tt.wantErrContains))
				}
				return
			}

			require.NoError(err)
			assert.Len(memberships, len(finalMgs))

			// Ensure the same set was found; all memberships found should have
			// been in the finalMgs map, and when they are all removed there
			// should be nothing left.
			for _, mship := range memberships {
				assert.Contains(finalMgs, mship.ManagedGroupId)
				delete(finalMgs, mship.ManagedGroupId)
			}
			assert.Len(finalMgs, 0)

			// assert.NoError(db.TestVerifyOplog(t, rw, got.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second)))
		})
	}
}
