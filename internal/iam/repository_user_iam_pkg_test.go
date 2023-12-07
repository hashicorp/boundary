// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package iam

import (
	"context"
	"testing"

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
