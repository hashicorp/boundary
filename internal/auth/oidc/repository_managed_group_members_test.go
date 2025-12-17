// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oidc_test

import (
	"context"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/auth/oidc/store"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_ManagedGroupMemberships(t *testing.T) {
	// This tests both managed group membership functions (set/list) as list is
	// always called as a return from set and we are validating the values that
	// come back against what we expect.

	// This test can be run in parallel; the subtests *cannot*.
	t.Parallel()

	// Note: using a test controller here for ease of setup as we need a working
	// dev OIDC auth method and associated accounts. This test is not making API
	// calls! It's accessing the repo directly via the test controller's
	// exposure of the underlying DB primitives.
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

	repo, err := oidc.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
	require.NotNil(t, repo)

	mgs := make([]*oidc.ManagedGroup, 0, 10)

	for i := 0; i < 100; i++ {
		mg := oidc.AllocManagedGroup()
		mg.AuthMethodId = authMethod.PublicId
		mg.Filter = oidc.TestFakeManagedGroupFilter
		got, err := repo.CreateManagedGroup(context.Background(), org.GetPublicId(), mg)
		require.NoError(t, err)
		mgs = append(mgs, got)
	}

	// Fetch valid OIDC accounts. One will be "static" where we will simply
	// ensure modifying the groups for the other doesn't affect it; the other
	// will be used for testing.
	var accts []*oidc.Account
	err = rw.SearchWhere(ctx, &accts, "", nil, db.WithLimit(2))
	require.NoError(t, err)
	require.Len(t, accts, 2)
	staticAccountId := accts[0].PublicId
	staticMembershipCount := 20
	accountId := accts[1].PublicId

	account := oidc.AllocAccount()
	account.PublicId = accountId

	tests := []struct {
		name string
		// If true, we will auto populate necessary values into the function
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
			name:         "valid fixed, static",
			validPrereqs: true,
			accountId:    staticAccountId,
			specificMgs:  mgs[0:staticMembershipCount],
		},
		{
			name:         "valid fixed",
			validPrereqs: true,
			specificMgs:  mgs[0:20],
		},
		{
			name:         "valid fixed, same values",
			validPrereqs: true,
			specificMgs:  mgs[0:20],
		},
		{
			name:         "valid fixed, new values",
			validPrereqs: true,
			specificMgs:  mgs[20:40],
		},
		{
			name:         "valid none",
			validPrereqs: true,
			wantMgsCount: 0,
		},
		{
			name:         "valid none, second test, testing gracefully aborting",
			validPrereqs: true,
			wantMgsCount: 0,
		},
		{
			name:         "valid fixed, prep for random",
			validPrereqs: true,
			specificMgs:  mgs[20:50],
		},
		{
			name:         "valid random",
			validPrereqs: true,
			wantMgsCount: 30,
		},
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
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			// We are intentionally carrying things over between tests to be
			// more realistic but that means we need correct versions, so update
			// them first.
			currMgs, ttime, err := repo.ListManagedGroups(ctx, authMethod.PublicId)
			require.NoError(err)
			// Transaction timestamp should be within ~10 seconds of now
			assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
			assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
			require.Len(currMgs, 100)
			currVersionMap := make(map[string]uint32, len(currMgs))
			for _, currMg := range currMgs {
				currVersionMap[currMg.PublicId] = currMg.Version
			}
			for _, mg := range mgs {
				mg.Version = currVersionMap[mg.PublicId]
			}

			var mgsToTest []*oidc.ManagedGroup
			var finalMgs map[string]*oidc.ManagedGroup
			// If we know the inputs are sane, create the test data
			if tt.validPrereqs {
				tt.authMethod = authMethod
				tt.account = oidc.AllocAccount()
				tt.account.PublicId = accountId
				if tt.accountId != "" {
					// This is for the test where we initially populate the
					// static account
					tt.account.PublicId = tt.accountId
				}
				mgsToTest = tt.specificMgs
				if mgsToTest == nil {
					// Select at random
					mgsToTest = make([]*oidc.ManagedGroup, tt.wantMgsCount)
					for i := 0; i < tt.wantMgsCount; i++ {
						mg := mgs[rand.Int()%len(mgs)]
						mgsToTest[i] = mg
					}
				}
				finalMgs = make(map[string]*oidc.ManagedGroup)
				for _, v := range mgsToTest {
					finalMgs[v.PublicId] = v
				}
			}

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
				// Randomly check a few to ensure the MembershipsByGroup function works
				members, err := repo.ListManagedGroupMembershipsByGroup(ctx, mship.ManagedGroupId)
				require.NoError(err)
				require.NotEmpty(members)
				var found bool
				for _, v := range members {
					if v.MemberId == tt.account.GetPublicId() {
						found = true
						break
					}
				}
				assert.True(found)
				assert.Contains(finalMgs, mship.ManagedGroupId)
				delete(finalMgs, mship.ManagedGroupId)
			}
			assert.Len(finalMgs, 0)

			// Now check that the static account still has the same memberships
			memberships, err = repo.ListManagedGroupMembershipsByMember(ctx, staticAccountId)
			require.NoError(err)
			assert.Len(memberships, staticMembershipCount)
			finalMgs = make(map[string]*oidc.ManagedGroup, staticMembershipCount)
			for _, mg := range mgs[0:staticMembershipCount] {
				finalMgs[mg.PublicId] = mg
			}
			for _, mship := range memberships {
				assert.Contains(finalMgs, mship.ManagedGroupId)
				delete(finalMgs, mship.ManagedGroupId)
			}
			assert.Len(finalMgs, 0)
		})
	}
}
