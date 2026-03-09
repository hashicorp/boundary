// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package iam

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	dbassert "github.com/hashicorp/boundary/internal/db/assert"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_associateUserWithAccounts(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	repo := TestRepo(t, conn, wrapper)
	org, _ := TestScopes(t, repo)
	authMethodId := testAuthMethod(t, conn, org.PublicId)
	authMethodId2 := testAuthMethod(t, conn, org.PublicId)

	type Ids struct {
		user  string
		accts []string
	}
	type args struct {
		Ids Ids
		opt []Option
	}
	tests := []struct {
		name        string
		args        args
		want        *User
		want1       *authAccount
		wantErr     bool
		wantErrCode errors.Code
		wantAssoc   bool
	}{
		{
			name: "simple",
			args: args{
				Ids: func() Ids {
					u := TestUser(t, repo, org.PublicId)
					a := testAccount(t, conn, org.PublicId, authMethodId, "")
					a2 := testAccount(t, conn, org.PublicId, authMethodId2, "")
					return Ids{user: u.PublicId, accts: []string{a.PublicId, a2.PublicId}}
				}(),
			},
		},
		{
			name: "two-accounts",
			args: args{
				Ids: func() Ids {
					u := TestUser(t, repo, org.PublicId)
					a := testAccount(t, conn, org.PublicId, authMethodId, "")
					a2 := testAccount(t, conn, org.PublicId, authMethodId, "")
					return Ids{user: u.PublicId, accts: []string{a.PublicId, a2.PublicId}}
				}(),
			},
			wantErr:     true,
			wantErrCode: errors.NotUnique,
		},
		{
			name: "missing-acctId",
			args: args{
				Ids: func() Ids {
					id := testId(t)

					return Ids{user: id}
				}(),
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name: "missing-userId",
			args: args{
				Ids: func() Ids {
					id := testId(t)
					return Ids{accts: []string{id}}
				}(),
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name: "already-properly-assoc",
			args: args{
				Ids: func() Ids {
					u := TestUser(t, repo, org.PublicId)
					a := testAccount(t, conn, org.PublicId, authMethodId, u.PublicId)
					return Ids{user: u.PublicId, accts: []string{a.PublicId}}
				}(),
				opt: []Option{WithDisassociate(true)},
			},
		},
		{
			name: "assoc-with-diff-user",
			args: args{
				Ids: func() Ids {
					u := TestUser(t, repo, org.PublicId)
					diffUser := TestUser(t, repo, org.PublicId)
					a := testAccount(t, conn, org.PublicId, authMethodId, diffUser.PublicId)
					return Ids{user: u.PublicId, accts: []string{a.PublicId}}
				}(),
			},
			wantErr:     true,
			wantErrCode: errors.AccountAlreadyAssociated,
		},
		{
			name: "assoc-with-diff-user-withDisassociateOption",
			args: args{
				Ids: func() Ids {
					u := TestUser(t, repo, org.PublicId)
					diffUser := TestUser(t, repo, org.PublicId)
					a := testAccount(t, conn, org.PublicId, authMethodId, diffUser.PublicId)
					return Ids{user: u.PublicId, accts: []string{a.PublicId}}
				}(),
			},
			wantErr:     true,
			wantErrCode: errors.AccountAlreadyAssociated,
		},
		{
			name: "bad-acct-id",
			args: args{
				Ids: func() Ids {
					u := TestUser(t, repo, org.PublicId)
					id := testId(t)
					return Ids{user: u.PublicId, accts: []string{id}}
				}(),
			},
			wantErr:     true,
			wantErrCode: errors.RecordNotFound,
		},
		{
			name: "bad-user-id-not-associated-account",
			args: args{
				Ids: func() Ids {
					id := testId(t)
					a := testAccount(t, conn, org.PublicId, authMethodId, "")
					return Ids{user: id, accts: []string{a.PublicId}}
				}(),
			},
			wantErr: false,
		},
		{
			name: "bad-user-id",
			args: args{
				Ids: func() Ids {
					id := testId(t)
					testUser := TestUser(t, repo, org.PublicId)
					a := testAccount(t, conn, org.PublicId, authMethodId, testUser.PublicId)
					return Ids{user: id, accts: []string{a.PublicId}}
				}(),
			},
			wantErr:     true,
			wantErrCode: errors.AccountAlreadyAssociated,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			err := associateUserWithAccounts(context.Background(), kms, rw, rw, tt.args.Ids.user, tt.args.Ids.accts, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.Truef(errors.Match(errors.T(tt.wantErrCode), err), "unexpected error %s", err)
				return
			}
			require.NoError(err)
			for _, id := range tt.args.Ids.accts {
				acct := allocAccount()
				acct.PublicId = id
				err = rw.LookupByPublicId(context.Background(), &acct)
				require.NoError(err)
				assert.Equal(tt.args.Ids.user, acct.IamUserId)
			}
		})
	}
}

func TestRepository_dissociateUserWithAccount(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	repo := TestRepo(t, conn, wrapper)
	org, _ := TestScopes(t, repo)
	authMethodId := testAuthMethod(t, conn, org.PublicId)
	authMethodId2 := testAuthMethod(t, conn, org.PublicId)

	type Ids struct {
		user  string
		accts []string
	}
	type args struct {
		Ids Ids
		opt []Option
	}
	tests := []struct {
		name        string
		args        args
		want        *User
		want1       *authAccount
		wantErr     bool
		wantErrCode errors.Code
	}{
		{
			name: "simple",
			args: args{
				Ids: func() Ids {
					u := TestUser(t, repo, org.PublicId)
					a := testAccount(t, conn, org.PublicId, authMethodId, u.PublicId)
					a2 := testAccount(t, conn, org.PublicId, authMethodId2, u.PublicId)
					return Ids{user: u.PublicId, accts: []string{a.PublicId, a2.PublicId}}
				}(),
			},
		},
		{
			name: "missing-acctId",
			args: args{
				Ids: func() Ids {
					id := testId(t)

					return Ids{user: id}
				}(),
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name: "missing-userId",
			args: args{
				Ids: func() Ids {
					id := testId(t)
					return Ids{accts: []string{id}}
				}(),
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name: "already-properly-disassoc",
			args: args{
				Ids: func() Ids {
					u := TestUser(t, repo, org.PublicId)
					a := testAccount(t, conn, org.PublicId, authMethodId, "")
					return Ids{user: u.PublicId, accts: []string{a.PublicId}}
				}(),
			},
			wantErr:     true,
			wantErrCode: errors.AccountAlreadyAssociated,
		},
		{
			name: "assoc-with-diff-user",
			args: args{
				Ids: func() Ids {
					u := TestUser(t, repo, org.PublicId)
					diffUser := TestUser(t, repo, org.PublicId)
					a := testAccount(t, conn, org.PublicId, authMethodId, diffUser.PublicId)
					return Ids{user: u.PublicId, accts: []string{a.PublicId}}
				}(),
			},
			wantErr:     true,
			wantErrCode: errors.AccountAlreadyAssociated,
		},
		{
			name: "bad-acct-id",
			args: args{
				Ids: func() Ids {
					u := TestUser(t, repo, org.PublicId)
					id := testId(t)
					return Ids{user: u.PublicId, accts: []string{id}}
				}(),
			},
			wantErr:     true,
			wantErrCode: errors.RecordNotFound,
		},
		{
			name: "bad-user-id-not-associated-account",
			args: args{
				Ids: func() Ids {
					id := testId(t)
					a := testAccount(t, conn, org.PublicId, authMethodId, "")
					return Ids{user: id, accts: []string{a.PublicId}}
				}(),
			},
			wantErr:     true,
			wantErrCode: errors.AccountAlreadyAssociated,
		},
		{
			name: "bad-user-id",
			args: args{
				Ids: func() Ids {
					id := testId(t)
					testUser := TestUser(t, repo, org.PublicId)
					a := testAccount(t, conn, org.PublicId, authMethodId, testUser.PublicId)
					return Ids{user: id, accts: []string{a.PublicId}}
				}(),
			},
			wantErr:     true,
			wantErrCode: errors.AccountAlreadyAssociated,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			underlyingDB, err := conn.SqlDB(ctx)
			require.NoError(err)
			dbassert := dbassert.New(t, underlyingDB)
			err = dissociateUserFromAccounts(context.Background(), kms, rw, rw, tt.args.Ids.user, tt.args.Ids.accts, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.Truef(errors.Match(errors.T(tt.wantErrCode), err), "unexpected error %s", err)
				return
			}
			require.NoError(err)

			for _, id := range tt.args.Ids.accts {
				acct := allocAccount()
				acct.PublicId = id
				dbassert.IsNull(&acct, "IamUserId")
			}
		})
	}
}

func TestRepository_ListUsers_internal(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	const testLimit = 10
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper, WithLimit(testLimit))
	org, _ := TestScopes(t, repo)

	type args struct {
		withOrgId string
		opt       []Option
	}
	tests := []struct {
		name      string
		createCnt int
		args      args
		wantCnt   int
		wantErr   bool
	}{
		{
			name:      "negative limit",
			createCnt: testLimit + 1,
			args: args{
				withOrgId: org.PublicId,
				opt:       []Option{WithLimit(-1)},
			},
			wantErr: true,
		},
		{
			name:      "default-limit",
			createCnt: testLimit + 1,
			args: args{
				withOrgId: org.PublicId,
			},
			wantCnt: testLimit,
			wantErr: false,
		},
		{
			name:      "custom-limit",
			createCnt: testLimit + 1,
			args: args{
				withOrgId: org.PublicId,
				opt:       []Option{WithLimit(3)},
			},
			wantCnt: 3,
			wantErr: false,
		},
		{
			name:      "bad-org",
			createCnt: 1,
			args: args{
				withOrgId: "bad-id",
			},
			wantCnt: 0,
			wantErr: false,
		},
	}
	type userInfo struct {
		email         string
		fullName      string
		primaryAcctId string
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			t.Cleanup(func() {
				db.TestDeleteWhere(t, conn, func() any { u := AllocUser(); return &u }(), "public_id != 'u_anon' and public_id != 'u_auth' and public_id != 'u_recovery'")
			})
			testUsers := []*User{}
			wantUserInfo := map[string]userInfo{}
			for i := 0; i < tt.createCnt; i++ {
				u := TestUser(t, repo, org.PublicId)
				testUsers = append(testUsers, u)
			}
			assert.Equal(tt.createCnt, len(testUsers))
			got, ttime, err := repo.ListUsers(context.Background(), []string{tt.args.withOrgId}, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantCnt, len(got))
			for _, u := range got {
				assert.Equal(wantUserInfo[u.PublicId], userInfo{
					email:         u.Email,
					fullName:      u.FullName,
					primaryAcctId: u.PrimaryAccountId,
				})
			}
			// Transaction timestamp should be within ~10 seconds of now
			assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
			assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		})
	}
	t.Run("withStartPageAfter", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()

		for i := 0; i < 10; i++ {
			_ = TestUser(t, repo, org.GetPublicId())
		}

		page1, ttime, err := repo.ListUsers(ctx, []string{org.GetPublicId()}, WithLimit(2))
		require.NoError(err)
		require.Len(page1, 2)
		// Transaction timestamp should be within ~10 seconds of now
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		page2, ttime, err := repo.ListUsers(ctx, []string{org.GetPublicId()}, WithLimit(2), WithStartPageAfterItem(page1[1]))
		require.NoError(err)
		require.Len(page2, 2)
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		for _, item := range page1 {
			assert.NotEqual(item.GetPublicId(), page2[0].GetPublicId())
			assert.NotEqual(item.GetPublicId(), page2[1].GetPublicId())
		}
		page3, ttime, err := repo.ListUsers(ctx, []string{org.GetPublicId()}, WithLimit(2), WithStartPageAfterItem(page2[1]))
		require.NoError(err)
		require.Len(page3, 2)
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		for _, item := range page2 {
			assert.NotEqual(item.GetPublicId(), page3[0].GetPublicId())
			assert.NotEqual(item.GetPublicId(), page3[1].GetPublicId())
		}
		page4, ttime, err := repo.ListUsers(ctx, []string{org.GetPublicId()}, WithLimit(2), WithStartPageAfterItem(page3[1]))
		require.NoError(err)
		assert.Len(page4, 2)
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		for _, item := range page3 {
			assert.NotEqual(item.GetPublicId(), page4[0].GetPublicId())
			assert.NotEqual(item.GetPublicId(), page4[1].GetPublicId())
		}
		page5, ttime, err := repo.ListUsers(ctx, []string{org.GetPublicId()}, WithLimit(2), WithStartPageAfterItem(page4[1]))
		require.NoError(err)
		assert.Len(page5, 2)
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		for _, item := range page4 {
			assert.NotEqual(item.GetPublicId(), page5[0].GetPublicId())
			assert.NotEqual(item.GetPublicId(), page5[1].GetPublicId())
		}
		page6, ttime, err := repo.ListUsers(ctx, []string{org.GetPublicId()}, WithLimit(2), WithStartPageAfterItem(page5[1]))
		require.NoError(err)
		assert.Empty(page6)
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))

		// Create 2 new users
		newR1 := TestUser(t, repo, org.GetPublicId())
		newR2 := TestUser(t, repo, org.GetPublicId())

		// since it will return newest to oldest, we get page1[1] first
		page7, ttime, err := repo.listUsersRefresh(
			ctx,
			time.Now().Add(-1*time.Second),
			[]string{org.GetPublicId()},
			WithLimit(1),
		)
		require.NoError(err)
		require.Len(page7, 1)
		require.Equal(page7[0].GetPublicId(), newR2.GetPublicId())
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))

		page8, ttime, err := repo.listUsersRefresh(
			context.Background(),
			time.Now().Add(-1*time.Second),
			[]string{org.GetPublicId()},
			WithLimit(1),
			WithStartPageAfterItem(page7[0]),
		)
		require.NoError(err)
		require.Len(page8, 1)
		require.Equal(page8[0].GetPublicId(), newR1.GetPublicId())
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
	})
}

func Test_listUserDeletedIds(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	org, _ := TestScopes(t, repo)
	r := TestUser(t, repo, org.GetPublicId())

	// Expect no entries at the start
	deletedIds, ttime, err := repo.listUserDeletedIds(ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(t, err)
	require.Empty(t, deletedIds)
	// Transaction timestamp should be within ~10 seconds of now
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))

	// Delete a user
	_, err = repo.DeleteUser(ctx, r.GetPublicId())
	require.NoError(t, err)

	// Expect a single entry
	deletedIds, ttime, err = repo.listUserDeletedIds(ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(t, err)
	require.Equal(t, []string{r.GetPublicId()}, deletedIds)
	// Transaction timestamp should be within ~10 seconds of now
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))

	// Try again with the time set to now, expect no entries
	deletedIds, ttime, err = repo.listUserDeletedIds(ctx, time.Now())
	require.NoError(t, err)
	require.Empty(t, deletedIds)
	// Transaction timestamp should be within ~10 seconds of now
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))
}

func Test_estimatedUserCount(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	sqlDb, err := conn.SqlDB(ctx)
	require.NoError(t, err)
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)

	// Run analyze to update estimate
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	// Check total entries at start, expect 3
	// u_anon, u_auth, and u_recovery
	numItems, err := repo.estimatedUserCount(ctx)
	require.NoError(t, err)
	assert.Equal(t, 3, numItems)

	iamRepo := TestRepo(t, conn, wrapper)
	org, _ := TestScopes(t, iamRepo)
	// Create a user, expect 1 entry
	u := TestUser(t, repo, org.GetPublicId())

	// Run analyze to update estimate
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)
	numItems, err = repo.estimatedUserCount(ctx)
	require.NoError(t, err)
	assert.Equal(t, 4, numItems)

	// Delete the user, expect 3 again
	_, err = repo.DeleteUser(ctx, u.GetPublicId())
	require.NoError(t, err)

	// Run analyze to update estimate
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	numItems, err = repo.estimatedUserCount(ctx)
	require.NoError(t, err)
	assert.Equal(t, 3, numItems)
}
