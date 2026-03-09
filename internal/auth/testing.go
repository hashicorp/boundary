// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package auth

import (
	"context"
	"sort"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/require"
)

type (
	TestAuthMethodWithAccountFunc           func(t *testing.T, conn *db.DB) (AuthMethod, Account)
	TestAuthMethodWithAccountInManagedGroup func(t *testing.T, conn *db.DB, kmsCache *kms.Kms, scopeId string) (AuthMethod, Account, ManagedGroup)
)

// ManagedGroupMemberAccount represents an entry from
// auth_managed_group_member_account.  These are used to determine the account
// ids where are a member of managed groups.  See: oidc and ldap managed groups
// as well as iam role grants.
type ManagedGroupMemberAccount struct {
	CreateTime     *timestamp.Timestamp
	MemberId       string
	ManagedGroupId string
	tableName      string
}

// SetTableName sets the table name.
func (a *ManagedGroupMemberAccount) SetTableName(n string) {
	a.tableName = n
}

// TableName returns the table name.
func (a *ManagedGroupMemberAccount) TableName() string {
	if a.tableName != "" {
		return a.tableName
	}
	return "auth_managed_group_member_account"
}

// TestSortManagedGroupMemberAccounts simply sorts them by public id to make
// comparisons a bit easier.
func TestSortManagedGroupMemberAccounts(t testing.TB, m []*ManagedGroupMemberAccount) {
	sort.Slice(m, func(a, b int) bool {
		return m[a].MemberId < m[b].MemberId
	})
}

// TestManagedGroupMemberAccounts retrieves the accounts with membership in the
// specified managed group.
func TestManagedGroupMemberAccounts(t *testing.T, conn *db.DB, managedGroupId string) []*ManagedGroupMemberAccount {
	var mgmAccts []*ManagedGroupMemberAccount
	ctx := context.Background()
	rw := db.New(conn)
	err := rw.SearchWhere(ctx, &mgmAccts, "managed_group_id = ?", []any{managedGroupId})
	require.NoError(t, err)
	TestSortManagedGroupMemberAccounts(t, mgmAccts)
	return mgmAccts
}
