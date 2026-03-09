// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ldap

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLdapManagedGroupRoleGrants ensures that user roles that
// include a ldap managed groups principal are properly returned from queries to
// auth_managed_group_member_account and iam repository.GrantsForUser(...)
//
// this test depends on changes made in 65/01_ldap.up.sql to the
// auth_managed_group_member_account view
func TestLdapManagedGroupRoleGrants(t *testing.T) {
	t.Parallel()
	const (
		testGrpName      = "testAdminGrp"
		testGrpName2     = "testUserGrp"
		testLdapUrl      = "ldap://test.ldap"
		testLoginName    = "test-user"
		testGrant        = "ids=*;type=*;actions=*"
		testClientId     = "alice-rp"
		testClientSecret = "fido"
		testIssuer       = "https://www.alice.com"
		testCallbackUrl  = "https://www.alice.com/callback"
	)
	testCtx := context.Background()
	testConn, _ := db.TestSetup(t, "postgres")
	testRootWrapper := db.TestWrapper(t)
	testRw := db.New(testConn)
	testKms := kms.TestKms(t, testConn, testRootWrapper)
	iamRepo := iam.TestRepo(t, testConn, testRootWrapper)
	testOrg, _ := iam.TestScopes(
		t,
		iamRepo,
		iam.WithSkipAdminRoleCreation(true),
		iam.WithSkipDefaultRoleCreation(true),
	)
	testScopeId := testOrg.GetPublicId()
	testGlobalDbWrapper, err := testKms.GetWrapper(testCtx, testScopeId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	ldapRepo, err := NewRepository(testCtx, testRw, testRw, testKms)
	require.NoError(t, err)

	testAm := TestAuthMethod(t, testConn, testGlobalDbWrapper, testScopeId, []string{testLdapUrl})
	testAcct := TestAccount(t, testConn, testAm, testLoginName, WithMemberOfGroups(testCtx, testGrpName))
	testManagedGrp := TestManagedGroup(t, testConn, testAm, []string{testGrpName})
	TestManagedGroup(t, testConn, testAm, []string{testGrpName2})

	testUser := iam.TestUser(t, iamRepo, testScopeId, iam.WithAccountIds(testAcct.PublicId))
	testRole := iam.TestRole(t, testConn, testScopeId)
	_ = iam.TestRoleGrant(t, testConn, testRole.GetPublicId(), testGrant)
	iam.TestManagedGroupRole(t, testConn, testRole.GetPublicId(), testManagedGrp.GetPublicId())

	// check the view to make sure it's correct, before trying the CTE used by
	// GrantsForUser(...) which depends on this view
	memberAccts, err := ldapRepo.ListManagedGroupMembershipsByMember(testCtx, testAcct.GetPublicId())
	require.NoError(t, err)
	require.Len(t, memberAccts, 1)
	require.Equal(t, testManagedGrp.GetPublicId(), memberAccts[0].GetManagedGroupId())
	require.Equal(t, testAcct.GetPublicId(), memberAccts[0].GetMemberId())
	t.Log("found managed group member acct: ", memberAccts[0].GetManagedGroupId(), memberAccts[0].GetMemberId())

	// okay, let's try the CTE and make sure the user has the grants given via
	// the ldap managed group
	// resource type does not matter here since testGrants has type=*
	tuples, err := iamRepo.GrantsForUser(testCtx, testUser.PublicId, []resource.Type{resource.Scope}, testScopeId)
	require.NoError(t, err)
	// De-dupe role IDs
	roleIds := make(map[string]bool, len(tuples))
	for _, tuple := range tuples {
		roleIds[tuple.RoleId] = true
	}
	t.Log("looking for role: ", testRole.GetPublicId())
	t.Log("found role/grant: ", tuples)
	assert.EqualValues(t, map[string]bool{testRole.GetPublicId(): true}, roleIds)

	// make sure a user without the appropriate managed group doesn't have grants
	testUserWithoutManagedGroupRole := iam.TestUser(t, iamRepo, testScopeId)
	tuples, err = iamRepo.GrantsForUser(testCtx, testUserWithoutManagedGroupRole.PublicId, []resource.Type{resource.Scope}, testScopeId)
	require.NoError(t, err)
	assert.Equal(t, 0, len(tuples))

	// okay, let's test a user that has both an oidc managed group and an ldap
	// managed group
	testOidcAm := oidc.TestAuthMethod(
		t, testConn, testGlobalDbWrapper, testScopeId, oidc.ActivePrivateState,
		testClientId, testClientSecret,
		oidc.WithSigningAlgs(oidc.RS256),
		oidc.WithIssuer(oidc.TestConvertToUrls(t, testIssuer)[0]),
		oidc.WithApiUrl(oidc.TestConvertToUrls(t, testCallbackUrl)[0]),
	)
	testOidcAcct := oidc.TestAccount(t, testConn, testOidcAm, "sub")
	testOidcManagedGrp := oidc.TestManagedGroup(t, testConn, testOidcAm, oidc.TestFakeManagedGroupFilter)
	oidc.TestManagedGroupMember(t, testConn, testOidcManagedGrp.GetPublicId(), testOidcAcct.GetPublicId())

	// add the oidc account to our test user....
	_, err = iamRepo.AddUserAccounts(testCtx, testUser.GetPublicId(), 2, []string{testOidcAcct.GetPublicId()})
	require.NoError(t, err)

	testRole2 := iam.TestRole(t, testConn, testScopeId)
	_ = iam.TestRoleGrant(t, testConn, testRole2.GetPublicId(), testGrant)
	iam.TestManagedGroupRole(t, testConn, testRole2.GetPublicId(), testOidcManagedGrp.GetPublicId())

	tuples, err = iamRepo.GrantsForUser(testCtx, testUser.GetPublicId(), []resource.Type{resource.SessionRecording}, testScopeId)
	require.NoError(t, err)
	assert.Equal(t, 2, len(tuples))
	t.Log("tuples:", tuples)

	assert.Equal(t,
		map[string]bool{testRole.GetPublicId(): true, testRole2.GetPublicId(): true},
		map[string]bool{tuples[0].RoleId: true, tuples[1].RoleId: true},
	)
}
