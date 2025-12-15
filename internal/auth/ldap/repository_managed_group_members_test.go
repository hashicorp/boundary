// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ldap_test

import (
	"context"
	"encoding/json"
	"math/rand"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/auth/ldap"
	"github.com/hashicorp/boundary/internal/auth/oidc/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_ManagedGroupMemberships(t *testing.T) {
	t.Parallel()

	testConn, _ := db.TestSetup(t, "postgres")
	testRootWrapper := db.TestWrapper(t)
	testRw := db.New(testConn)

	testKms := kms.TestKms(t, testConn, testRootWrapper)
	iamRepo := iam.TestRepo(t, testConn, testRootWrapper)

	testCtx := context.Background()
	testGlobalDbWrapper, err := testKms.GetWrapper(testCtx, "global", kms.KeyPurposeDatabase)
	require.NoError(t, err)

	testAuthMethod := ldap.TestAuthMethod(t, testConn, testGlobalDbWrapper, "global", []string{"ldaps://ldap1"})
	testAuthMethodStatic := ldap.TestAuthMethod(t, testConn, testGlobalDbWrapper, "global", []string{"ldaps://ldap1"})

	repo, err := ldap.NewRepository(testCtx, testRw, testRw, testKms)
	require.NoError(t, err)
	require.NotNil(t, repo)

	// make some groups with GroupNames which will initially match no accounts
	mgs := make([]*ldap.ManagedGroup, 0, 100)
	for i := 0; i < 100; i++ {
		got := ldap.TestManagedGroup(t, testConn, testAuthMethod, []string{"foo", "bar"})
		mgs = append(mgs, got)
	}

	testUser := iam.TestUser(t, iamRepo, "global")
	staticAccount := ldap.TestAccount(t, testConn, testAuthMethodStatic, "test-static-login-name", ldap.WithMemberOfGroups(testCtx, "static"))
	staticGroup := ldap.TestManagedGroup(t, testConn, testAuthMethod, []string{"static"})
	const staticMembershipCount = 1

	testGroupNames := []string{"admin", "users"}
	testGroupNamesEncodes, err := json.Marshal(testGroupNames)
	require.NoError(t, err)

	// Fetch existing default admin user u_1234567890 which will have 20 static
	// groups associated with it.  Then associate a new ldap account to that
	// user
	account := ldap.TestAccount(t, testConn, testAuthMethod, "test-login-name", ldap.WithMemberOfGroups(testCtx, testGroupNames...))

	adminUser, _, err := iamRepo.LookupUser(testCtx, testUser.PublicId)
	require.NoError(t, err)
	accts, err := iamRepo.AddUserAccounts(testCtx, testUser.PublicId, adminUser.Version, []string{account.PublicId, staticAccount.PublicId})
	require.NoError(t, err)
	require.Len(t, accts, 2)

	tests := []struct {
		name            string
		account         *ldap.Account
		wantMgsCount    int
		specificMgs     []*ldap.ManagedGroup
		wantErr         errors.Code
		wantErrContains string
	}{
		{
			name:        "valid fixed",
			account:     account,
			specificMgs: mgs[0:20],
		},
		{
			name:        "valid fixed, same values",
			account:     account,
			specificMgs: mgs[0:20],
		},
		{
			name:        "valid fixed, new values",
			account:     account,
			specificMgs: mgs[20:40],
		},
		{
			name:         "valid none",
			account:      account,
			wantMgsCount: 0,
		},
		{
			name:         "valid none, second test, testing gracefully aborting",
			account:      account,
			wantMgsCount: 0,
		},
		{
			name:        "valid fixed, prep for random",
			account:     account,
			specificMgs: mgs[20:50],
		},
		{
			name:         "valid random",
			account:      account,
			wantMgsCount: 30,
		},
		{
			name:         "valid random, second test",
			account:      account,
			wantMgsCount: 20,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			// We are intentionally carrying things over between tests to be
			// more realistic but that means we need correct versions, so update
			// them first.
			currMgs, ttime, err := repo.ListManagedGroups(testCtx, testAuthMethod.PublicId)
			require.NoError(err)
			assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
			assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
			require.Len(currMgs, 101)
			currVersionMap := make(map[string]uint32, len(currMgs))
			for _, currMg := range currMgs {
				currVersionMap[currMg.PublicId] = currMg.Version
			}
			for _, mg := range mgs {
				mg.Version = currVersionMap[mg.PublicId]
			}

			var mgsToTest []*ldap.ManagedGroup
			var finalMgs map[string]*ldap.ManagedGroup

			mgsToTest = tc.specificMgs
			if mgsToTest == nil {
				// Select at random
				mgsToTest = make([]*ldap.ManagedGroup, tc.wantMgsCount)
				for i := 0; i < tc.wantMgsCount; i++ {
					mg := mgs[rand.Int()%len(mgs)]
					mgsToTest[i] = mg
				}
			}
			finalMgs = make(map[string]*ldap.ManagedGroup)
			for _, v := range mgsToTest {
				v.GroupNames = string(testGroupNamesEncodes)
				v, _, err = repo.UpdateManagedGroup(testCtx, "global", v, v.Version, []string{"GroupNames"})
				require.NoError(err)
				finalMgs[v.PublicId] = v
			}

			// Ensure the same set was found; all memberships found should have
			// been in the finalMgs map, and when they are all removed there
			// should be nothing left.
			for _, mship := range mgsToTest {
				// Randomly check a few to ensure the MembershipsByGroup function works
				members, err := repo.ListManagedGroupMembershipsByGroup(testCtx, mship.PublicId)
				require.NoError(err)
				require.NotEmpty(members)
				var found bool
				for _, v := range members {
					if v.MemberId == tc.account.GetPublicId() {
						found = true
						break
					}
				}
				assert.True(found)
				delete(finalMgs, mship.PublicId)
			}
			assert.Len(finalMgs, 0)

			// Now check that the static account still has the same memberships
			memberships, err := repo.ListManagedGroupMembershipsByMember(testCtx, staticAccount.PublicId)
			require.NoError(err)
			assert.Len(memberships, staticMembershipCount)
			assert.Equal(memberships[0].ManagedGroupId, staticGroup.PublicId)
		})
	}
	t.Run("ListManagedGroupMembershipsByGroup-invalid-parameters", func(t *testing.T) {
		got, err := repo.ListManagedGroupMembershipsByGroup(testCtx, "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "missing managed group id")
		assert.Nil(t, got)
	})
	t.Run("ListManagedGroupMembershipsByMember-invalid-parameter", func(t *testing.T) {
		got, err := repo.ListManagedGroupMembershipsByMember(testCtx, "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "missing account id")
		assert.Nil(t, got)
	})
}

func TestManagedGroupMemberAccount_SetTableName(t *testing.T) {
	t.Parallel()
	allocFn := func() *ldap.ManagedGroupMemberAccount {
		return &ldap.ManagedGroupMemberAccount{
			ManagedGroupMemberAccount: &store.ManagedGroupMemberAccount{},
		}
	}
	defaultTableName := "auth_ldap_managed_group_member_account"
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
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			def := allocFn()
			require.Equal(defaultTableName, def.TableName())
			m := allocFn()
			m.SetTableName(tc.setNameTo)
			assert.Equal(tc.want, m.TableName())
		})
	}
}
