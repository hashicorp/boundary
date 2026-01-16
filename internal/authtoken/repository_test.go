// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package authtoken

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/hashicorp/boundary/internal/authtoken/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
)

func TestRepository_New(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)

	type args struct {
		r    db.Reader
		w    db.Writer
		kms  *kms.Kms
		opts []Option
	}

	tests := []struct {
		name       string
		args       args
		want       *Repository
		wantIsErr  errors.Code
		wantErrMsg string
	}{
		{
			name: "valid default limit",
			args: args{
				r:    rw,
				w:    rw,
				kms:  kmsCache,
				opts: []Option{},
			},
			want: &Repository{
				reader:              rw,
				writer:              rw,
				kms:                 kmsCache,
				limit:               db.DefaultLimit,
				timeToLiveDuration:  defaultTokenTimeToLiveDuration,
				timeToStaleDuration: defaultTokenTimeToStaleDuration,
			},
		},
		{
			name: "valid new limit",
			args: args{
				r:   rw,
				w:   rw,
				kms: kmsCache,
				opts: []Option{
					WithLimit(5),
				},
			},
			want: &Repository{
				reader:              rw,
				writer:              rw,
				kms:                 kmsCache,
				limit:               5,
				timeToLiveDuration:  defaultTokenTimeToLiveDuration,
				timeToStaleDuration: defaultTokenTimeToStaleDuration,
			},
		},
		{
			name: "valid token time to live",
			args: args{
				r:   rw,
				w:   rw,
				kms: kmsCache,
				opts: []Option{
					WithTokenTimeToLiveDuration(1 * time.Hour),
				},
			},
			want: &Repository{
				reader:              rw,
				writer:              rw,
				kms:                 kmsCache,
				limit:               db.DefaultLimit,
				timeToLiveDuration:  1 * time.Hour,
				timeToStaleDuration: defaultTokenTimeToStaleDuration,
			},
		},
		{
			name: "valid token time to stale",
			args: args{
				r:   rw,
				w:   rw,
				kms: kmsCache,
				opts: []Option{
					WithTokenTimeToStaleDuration(1 * time.Hour),
				},
			},
			want: &Repository{
				reader:              rw,
				writer:              rw,
				kms:                 kmsCache,
				limit:               db.DefaultLimit,
				timeToStaleDuration: 1 * time.Hour,
				timeToLiveDuration:  defaultTokenTimeToLiveDuration,
			},
		},

		{
			name: "nil-reader",
			args: args{
				r:   nil,
				w:   rw,
				kms: kmsCache,
			},
			want:       nil,
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "authtoken.NewRepository: nil db reader: parameter violation: error #100",
		},
		{
			name: "nil-writer",
			args: args{
				r:   rw,
				w:   nil,
				kms: kmsCache,
			},
			want:       nil,
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "authtoken.NewRepository: nil db writer: parameter violation: error #100",
		},
		{
			name: "nil-kms",
			args: args{
				r:   rw,
				w:   rw,
				kms: nil,
			},
			want:       nil,
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "authtoken.NewRepository: nil kms: parameter violation: error #100",
		},
		{
			name: "all-nils",
			args: args{
				r:   nil,
				w:   nil,
				kms: nil,
			},
			want:       nil,
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "authtoken.NewRepository: nil db reader: parameter violation: error #100",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			got, err := NewRepository(context.Background(), tt.args.r, tt.args.w, tt.args.kms, tt.args.opts...)
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "Unexpected error %s", err)
				assert.Equal(tt.wantErrMsg, err.Error())
				return
			}
			assert.NoError(err)
			assert.NotNil(got)
			assert.Equal(tt.want, got)
		})
	}
}

func TestRepository_CreateAuthToken(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	repo := iam.TestRepo(t, conn, wrapper)

	org1, _ := iam.TestScopes(t, repo)
	am := password.TestAuthMethods(t, conn, org1.GetPublicId(), 1)[0]
	aAcct := password.TestAccount(t, conn, am.GetPublicId(), "name1")
	iam.TestSetPrimaryAuthMethod(t, repo, org1, am.PublicId)
	u1 := iam.TestUser(t, repo, org1.PublicId, iam.WithAccountIds(aAcct.PublicId))

	org2, _ := iam.TestScopes(t, repo)
	u2 := iam.TestUser(t, repo, org2.GetPublicId())

	testId, err := NewAuthTokenId(ctx)
	require.NoError(t, err)

	tests := []struct {
		name       string
		iamUser    *iam.User
		authAcctId string
		opt        []Option
		want       *AuthToken
		wantErr    bool
	}{
		{
			name:       "valid",
			iamUser:    u1,
			authAcctId: aAcct.GetPublicId(),
			want: &AuthToken{
				AuthToken: &store.AuthToken{
					AuthAccountId: aAcct.GetPublicId(),
				},
			},
		},
		{
			name:       "WithPublicId-WithStatus",
			iamUser:    u1,
			authAcctId: aAcct.GetPublicId(),
			opt:        []Option{WithPublicId(testId), WithStatus(PendingStatus)},
			want: &AuthToken{
				AuthToken: &store.AuthToken{
					AuthAccountId: aAcct.GetPublicId(),
					PublicId:      testId,
					Status:        string(PendingStatus),
				},
			},
		},
		{
			name:       "unconnected-authaccount-user",
			iamUser:    u2,
			authAcctId: aAcct.GetPublicId(),
			wantErr:    true,
		},
		{
			name:    "no-authacctid",
			iamUser: u1,
			wantErr: true,
		},
		{
			name:       "no-userid",
			authAcctId: aAcct.GetPublicId(),
			wantErr:    true,
		},
		{
			name:       "invalid-authacctid",
			iamUser:    u1,
			authAcctId: "this_is_invalid",
			wantErr:    true,
		},
		{
			name:       "invalid-userid",
			iamUser:    func() *iam.User { u := u1.Clone().(*iam.User); u.PublicId = "this_is_invalid"; return u }(),
			authAcctId: aAcct.GetPublicId(),
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(ctx, rw, rw, kms)
			require.NoError(err)
			require.NotNil(repo)
			got, err := repo.CreateAuthToken(ctx, tt.iamUser, tt.authAcctId, tt.opt...)
			if tt.wantErr {
				assert.Error(err)
				assert.Nil(got)
				return
			}
			require.NoError(err, "Got error for CreateAuthToken(ctx, %v, %v)", tt.iamUser, tt.authAcctId)
			assert.NotNil(got)
			db.AssertPublicId(t, globals.AuthTokenPrefix, got.PublicId)
			assert.Equal(tt.authAcctId, got.GetAuthAccountId())
			assert.Equal(got.CreateTime, got.UpdateTime)
			assert.Equal(got.CreateTime, got.ApproximateLastAccessTime)

			opts := getOpts(tt.opt...)
			if opts.withPublicId != "" {
				assert.Equal(opts.withPublicId, got.PublicId)
			}
			if opts.withStatus != "" {
				assert.Equal(string(opts.withStatus), got.Status)
			}

			// We should find no oplog since tokens are not replicated, so they don't need oplog entries.
			assert.Error(db.TestVerifyOplog(t, rw, got.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_CREATE)))
		})
	}
}

func TestRepository_LookupAuthToken(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	repo := iam.TestRepo(t, conn, wrapper)
	org, _ := iam.TestScopes(t, repo)
	at := TestAuthToken(t, conn, kms, org.GetPublicId())
	at.Token = ""
	at.CtToken = nil
	at.KeyId = ""

	badId, err := NewAuthTokenId(ctx)
	require.NoError(t, err)
	require.NotNil(t, badId)

	tests := []struct {
		name       string
		id         string
		want       *AuthToken
		wantIsErr  errors.Code
		wantErrMsg string
	}{
		{
			name: "found",
			id:   at.GetPublicId(),
			want: at,
		},
		{
			name: "not-found",
			id:   badId,
			want: nil,
		},
		{
			name:       "bad-public-id",
			id:         "",
			want:       nil,
			wantIsErr:  errors.InvalidPublicId,
			wantErrMsg: "authtoken.(Repository).LookupAuthToken: missing public id: parameter violation: error #102",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(ctx, rw, rw, kms)
			require.NoError(err)
			require.NotNil(repo)

			got, err := repo.LookupAuthToken(ctx, tt.id)
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "Unexpected error %s", err)
				assert.Equal(tt.wantErrMsg, err.Error())
				return
			}
			assert.NoError(err)
			if got == nil {
				assert.Nil(tt.want)
				return
			}
			require.NotNil(tt.want, "got %v, wanted nil", got)
			// TODO: This test fails by a very small amount -- 500 nanos ish in
			// my experience -- if they are required to be equal. I think this
			// is because the resolution of the timestamp in the db does not
			// match the resolution in Go code. But might be worth checking
			// into.
			wantGoTimeExpr := tt.want.AuthToken.GetExpirationTime().Timestamp.AsTime()
			gotGoTimeExpr := got.AuthToken.GetExpirationTime().Timestamp.AsTime()
			assert.WithinDuration(wantGoTimeExpr, gotGoTimeExpr, time.Millisecond)
			tt.want.AuthToken.ExpirationTime = got.AuthToken.ExpirationTime
			assert.Empty(cmp.Diff(tt.want.AuthToken, got.AuthToken, protocmp.Transform()))
		})
	}
}

func TestRepository_ValidateToken(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	lastAccessedUpdateDuration = 0
	timeSkew = 20 * time.Millisecond

	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	repo, err := NewRepository(ctx, rw, rw, kms)

	require.NoError(t, err)
	require.NotNil(t, repo)

	org, _ := iam.TestScopes(t, iamRepo)
	at := TestAuthToken(t, conn, kms, org.GetPublicId())
	atToken := at.GetToken()
	at.Token = ""
	at.CtToken = nil
	at.KeyId = ""
	atTime := at.GetApproximateLastAccessTime()
	require.NotNil(t, atTime)

	badId, err := NewAuthTokenId(ctx)
	require.NoError(t, err)
	require.NotNil(t, badId)

	badToken, err := newAuthToken(ctx)
	require.NoError(t, err)
	require.NotNil(t, badToken)

	tests := []struct {
		name       string
		id         string
		token      string
		want       *AuthToken
		wantIsErr  errors.Code
		wantErrMsg string
	}{
		{
			name:  "exists",
			id:    at.GetPublicId(),
			token: atToken,
			want:  at,
		},
		{
			name:  "doesnt-exist",
			id:    badId,
			token: badToken.Token,
			want:  nil,
		},
		{
			name:       "empty-token",
			id:         at.GetPublicId(),
			token:      "",
			want:       nil,
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "authtoken.(Repository).ValidateToken: missing token: parameter violation: error #100",
		},
		{
			name:      "mismatched-token",
			id:        at.GetPublicId(),
			token:     badToken.Token,
			want:      nil,
			wantIsErr: errors.Unknown,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := repo.ValidateToken(ctx, tt.id, tt.token)

			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "Unexpected error %s", err)
				assert.Equal(tt.wantErrMsg, err.Error())
				return
			}
			assert.NoError(err)
			if got == nil {
				assert.Nil(tt.want)
				// No need to compare updated time if we didn't get an initial auth token to compare against.
				return
			}
			require.NotNil(tt.want, "Got %v but wanted nil", got)

			// NOTE: See comment in LookupAuthToken about this logic
			wantGoTimeExpr := tt.want.AuthToken.GetExpirationTime().AsTime()
			gotGoTimeExpr := got.AuthToken.GetExpirationTime().AsTime()
			assert.WithinDuration(wantGoTimeExpr, gotGoTimeExpr, time.Millisecond)
			tt.want.AuthToken.ExpirationTime = got.AuthToken.ExpirationTime
			assert.Empty(cmp.Diff(tt.want.AuthToken, got.AuthToken, protocmp.Transform()))

			// preTime1 should be the value prior to the ValidateToken was called so it should equal creation time
			preTime1 := got.GetApproximateLastAccessTime()
			require.NoError(err)
			assert.True(preTime1.AsTime().Equal(atTime.AsTime()), "Create time %q doesn't match the time from the first call to MaybeUpdateLastAccesssed: %q.", atTime, preTime1)

			// Enable the duration which limits how frequently a token's approximate last accessed time can be updated
			// so the next call doesn't cause the last accessed time to be updated.
			lastAccessedUpdateDuration = 1 * time.Hour

			got2, err := repo.ValidateToken(ctx, tt.id, tt.token)
			assert.NoError(err)
			preTime2 := got2.GetApproximateLastAccessTime().GetTimestamp()
			assert.True(preTime2.AsTime().After(preTime1.AsTime()), "First updated time %q was not after the creation time %q", preTime2, preTime1)

			// We should find no oplog since tokens are not replicated, so they don't need oplog entries.
			assert.Error(db.TestVerifyOplog(t, rw, got.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_UPDATE)))

			got3, err := repo.ValidateToken(ctx, tt.id, tt.token)
			require.NoError(err)
			preTime3 := got3.GetApproximateLastAccessTime()
			assert.True(preTime3.AsTime().Equal(preTime2.AsTime()), "The 3rd timestamp %q was not equal to the second time %q", preTime3, preTime2)
		})
	}
}

func TestRepository_ValidateToken_expired(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)

	org, _ := iam.TestScopes(t, iamRepo)
	baseAT := TestAuthToken(t, conn, kms, org.GetPublicId())
	baseAT.GetAuthAccountId()
	aAcct := allocAuthAccount()
	aAcct.PublicId = baseAT.GetAuthAccountId()
	require.NoError(t, rw.LookupByPublicId(context.Background(), aAcct))
	iamUser, _, err := iamRepo.LookupUser(context.Background(), aAcct.GetIamUserId())
	require.NoError(t, err)
	require.NotNil(t, iamUser)

	tests := []struct {
		name               string
		staleDuration      time.Duration
		expirationDuration time.Duration
		wantReturned       bool
	}{
		{
			name:               "not-stale-or-expired",
			staleDuration:      defaultTokenTimeToStaleDuration,
			expirationDuration: defaultTokenTimeToLiveDuration,
			wantReturned:       true,
		},
		{
			name:               "stale",
			staleDuration:      1 * time.Millisecond,
			expirationDuration: defaultTokenTimeToLiveDuration,
			wantReturned:       false,
		},
		{
			name:               "expired",
			staleDuration:      defaultTokenTimeToStaleDuration,
			expirationDuration: 1 * time.Millisecond,
			wantReturned:       false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			ctx := context.Background()

			timeSkew = 20 * time.Millisecond

			repo, err := NewRepository(ctx, rw, rw, kms,
				WithTokenTimeToLiveDuration(tt.expirationDuration),
				WithTokenTimeToStaleDuration(tt.staleDuration))
			require.NoError(err)
			require.NotNil(repo)

			at, err := repo.CreateAuthToken(ctx, iamUser, baseAT.GetAuthAccountId())
			require.NoError(err)

			got, err := repo.ValidateToken(ctx, at.GetPublicId(), at.GetToken())
			require.NoError(err)

			if tt.wantReturned {
				assert.NotNil(got)
			} else {
				// We should find no oplog since tokens are not replicated, so they don't need oplog entries.
				assert.Error(db.TestVerifyOplog(t, rw, at.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_DELETE)))
				assert.Nil(got)
			}
		})
	}
}

func TestRepository_DeleteAuthToken(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	repo := iam.TestRepo(t, conn, wrapper)
	org, _ := iam.TestScopes(t, repo)
	at := TestAuthToken(t, conn, kms, org.GetPublicId())
	badId, err := NewAuthTokenId(ctx)
	require.NoError(t, err)
	require.NotNil(t, badId)

	tests := []struct {
		name       string
		id         string
		want       int
		wantIsErr  errors.Code
		wantErrMsg string
	}{
		{
			name: "found",
			id:   at.GetPublicId(),
			want: 1,
		},
		{
			name: "not-found",
			id:   badId,
			want: 0,
		},
		{
			name:       "empty-public-id",
			id:         "",
			want:       0,
			wantIsErr:  errors.InvalidPublicId,
			wantErrMsg: "authtoken.(Repository).DeleteAuthToken: missing public id: parameter violation: error #102",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(ctx, rw, rw, kms)
			require.NoError(err)
			require.NotNil(repo)

			got, err := repo.DeleteAuthToken(ctx, tt.id)
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "Unexpected error %s", err)
				assert.Equal(tt.wantErrMsg, err.Error())
				return
			}
			assert.NoError(err)
			assert.Equal(tt.want, got, "row count")
			if tt.want != 0 {
				// We should find no oplog since tokens are not replicated, so they don't need oplog entries.
				assert.Error(db.TestVerifyOplog(t, rw, tt.id, db.WithOperation(oplog.OpType_OP_TYPE_DELETE)))
			}
		})
	}
}

func TestRepository_ListAuthTokens(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	repo := iam.TestRepo(t, conn, wrapper)
	org, _ := iam.TestScopes(t, repo)
	at1 := TestAuthToken(t, conn, kms, org.GetPublicId())
	at1.Token = ""
	at1.KeyId = ""
	at2 := TestAuthToken(t, conn, kms, org.GetPublicId())
	at2.Token = ""
	at2.KeyId = ""
	at3 := TestAuthToken(t, conn, kms, org.GetPublicId())
	at3.Token = ""
	at3.KeyId = ""

	emptyOrg, _ := iam.TestScopes(t, repo)

	tests := []struct {
		name      string
		orgId     string
		want      []*AuthToken
		wantTTime time.Time
	}{
		{
			name:      "populated",
			orgId:     org.GetPublicId(),
			want:      []*AuthToken{at1, at2, at3},
			wantTTime: time.Now(),
		},
		{
			name:      "empty",
			orgId:     emptyOrg.GetPublicId(),
			want:      []*AuthToken{},
			wantTTime: time.Now(),
		},
		{
			name:      "empty-org-id",
			orgId:     "",
			want:      []*AuthToken{},
			wantTTime: time.Now(),
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(ctx, rw, rw, kms)
			require.NoError(err)
			require.NotNil(repo)
			got, ttime, err := repo.listAuthTokens(ctx, []string{tt.orgId})
			assert.NoError(err)
			sort.Slice(tt.want, func(i, j int) bool { return tt.want[i].PublicId < tt.want[j].PublicId })
			sort.Slice(got, func(i, j int) bool { return got[i].PublicId < got[j].PublicId })
			assert.Empty(cmp.Diff(tt.want, got, protocmp.Transform()), "row count")
			// Transaction timestamp should be within ~10 seconds of now
			assert.True(tt.wantTTime.Before(ttime.Add(10 * time.Second)))
			assert.True(tt.wantTTime.After(ttime.Add(-10 * time.Second)))
		})
	}
	t.Run("withStartPageAfter", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		for i := 0; i < 7; i++ {
			at := TestAuthToken(t, conn, kms, org.GetPublicId())
			at.Token = ""
			at.KeyId = ""
		}

		repo, err := NewRepository(ctx, rw, rw, kms)
		require.NoError(err)
		page1, ttime, err := repo.listAuthTokens(ctx, []string{org.GetPublicId()}, WithLimit(2))
		require.NoError(err)
		require.Len(page1, 2)
		// Transaction timestamp should be within ~10 seconds of now
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		page2, ttime, err := repo.listAuthTokens(ctx, []string{org.GetPublicId()}, WithLimit(2), WithStartPageAfterItem(page1[1]))
		require.NoError(err)
		require.Len(page2, 2)
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		for _, item := range page1 {
			assert.NotEqual(item.GetPublicId(), page2[0].GetPublicId())
			assert.NotEqual(item.GetPublicId(), page2[1].GetPublicId())
		}
		page3, ttime, err := repo.listAuthTokens(ctx, []string{org.GetPublicId()}, WithLimit(2), WithStartPageAfterItem(page2[1]))
		require.NoError(err)
		require.Len(page3, 2)
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		for _, item := range page2 {
			assert.NotEqual(item.GetPublicId(), page3[0].GetPublicId())
			assert.NotEqual(item.GetPublicId(), page3[1].GetPublicId())
		}
		page4, ttime, err := repo.listAuthTokens(ctx, []string{org.GetPublicId()}, WithLimit(2), WithStartPageAfterItem(page3[1]))
		require.NoError(err)
		require.Len(page4, 2)
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		for _, item := range page3 {
			assert.NotEqual(item.GetPublicId(), page4[0].GetPublicId())
			assert.NotEqual(item.GetPublicId(), page4[1].GetPublicId())
		}
		page5, ttime, err := repo.listAuthTokens(ctx, []string{org.GetPublicId()}, WithLimit(2), WithStartPageAfterItem(page4[1]))
		require.NoError(err)
		require.Len(page5, 2)
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		for _, item := range page4 {
			assert.NotEqual(item.GetPublicId(), page5[0].GetPublicId())
			assert.NotEqual(item.GetPublicId(), page5[1].GetPublicId())
		}
		page6, ttime, err := repo.listAuthTokens(ctx, []string{org.GetPublicId()}, WithLimit(2), WithStartPageAfterItem(page5[1]))
		require.NoError(err)
		require.Empty(page6)
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))

		// Create 2 new auth tokens
		newAt1 := TestAuthToken(t, conn, kms, org.GetPublicId())
		newAt1.Token = ""
		newAt1.KeyId = ""
		newAt2 := TestAuthToken(t, conn, kms, org.GetPublicId())
		newAt2.Token = ""
		newAt2.KeyId = ""

		// since it will return newest to oldest, we get page1[1] first
		page7, ttime, err := repo.listAuthTokensRefresh(
			ctx,
			time.Now().Add(-1*time.Second),
			[]string{org.GetPublicId()},
			WithLimit(1),
		)
		require.NoError(err)
		require.Len(page7, 1)
		require.Equal(page7[0].GetPublicId(), newAt2.GetPublicId())
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))

		page8, ttime, err := repo.listAuthTokensRefresh(
			context.Background(),
			time.Now().Add(-1*time.Second),
			[]string{org.GetPublicId()},
			WithLimit(1),
			WithStartPageAfterItem(page7[0]),
		)
		require.NoError(err)
		require.Len(page8, 1)
		require.Equal(page8[0].GetPublicId(), newAt1.GetPublicId())
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
	})
}

func TestRepository_ListAuthTokens_Multiple_Scopes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	org, proj := iam.TestScopes(t, iamRepo)

	const numPerScope = 10
	var total int
	for i := 0; i < numPerScope; i++ {
		TestAuthToken(t, conn, kms, "global")
		total++
		TestAuthToken(t, conn, kms, org.GetPublicId())
		total++
	}

	got, ttime, err := repo.listAuthTokens(ctx, []string{"global", org.GetPublicId(), proj.GetPublicId()})
	require.NoError(t, err)
	assert.Equal(t, total, len(got)) // Transaction timestamp should be within ~10 seconds of now
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))
}

func Test_IssuePendingToken(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	rootWrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, rootWrapper)
	repo, err := NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)

	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, rootWrapper))

	tests := []struct {
		name            string
		tokenRequestId  string
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name:            "missing-id",
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing token request id",
		},
		{
			name: "not-found",
			tokenRequestId: func() string {
				tokenPublicId, err := NewAuthTokenId(ctx)
				require.NoError(t, err)
				tk := TestAuthToken(t, conn, kmsCache, org.PublicId, WithPublicId(tokenPublicId))
				return tk.PublicId
			}(),
			wantErrMatch:    errors.T(errors.RecordNotFound),
			wantErrContains: "pending auth token",
		},
		{
			name: "success",
			tokenRequestId: func() string {
				tokenPublicId, err := NewAuthTokenId(ctx)
				require.NoError(t, err)
				tk := TestAuthToken(t, conn, kmsCache, org.PublicId, WithStatus(PendingStatus), WithPublicId(tokenPublicId))
				return tk.PublicId
			}(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			tk, err := repo.IssueAuthToken(ctx, tt.tokenRequestId)
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "wanted %s and got: %+v", tt.wantErrMatch.Code, err)
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}
				return
			}
			require.NoError(err)
			assert.NotEmpty(tk)
			accessTime := tk.GetApproximateLastAccessTime()
			createTime := tk.GetCreateTime().GetTimestamp()
			assert.True(accessTime.AsTime().After(createTime.AsTime()), "last access time %q was not after the creation time %q", accessTime, createTime)
		})
	}
}

func Test_CloseExpiredPendingTokens(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	rootWrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, rootWrapper)
	repo, err := NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)

	iamRepo := iam.TestRepo(t, conn, rootWrapper)
	org, _ := iam.TestScopes(t, iamRepo)
	user := iam.TestUser(t, iamRepo, org.GetPublicId())
	databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	createWith := func(cnt int, expIn time.Duration, status Status) {
		authMethods := password.TestAuthMethods(t, conn, org.PublicId, 1)
		authMethodId := authMethods[0].PublicId

		accts := password.TestMultipleAccounts(t, conn, authMethodId, cnt)
		for i := 0; i < cnt; i++ {
			user, _, err = iamRepo.LookupUser(ctx, user.GetPublicId())
			require.NoError(t, err)

			_, _ = iamRepo.AddUserAccounts(ctx, user.GetPublicId(), user.GetVersion(), []string{accts[i].GetPublicId()})

			at := allocAuthToken()
			id, err := NewAuthTokenId(ctx)
			require.NoError(t, err)
			at.PublicId = id
			exp := timestamppb.New(time.Now().Add(expIn).Truncate(time.Second))
			at.ExpirationTime = &timestamp.Timestamp{Timestamp: exp}
			at.Status = string(status)
			at.AuthAccountId = accts[i].PublicId
			keyId, err := databaseWrapper.KeyId(ctx)
			require.NoError(t, err)
			at.KeyId = keyId
			at.CtToken = []byte(id)
			err = rw.Create(ctx, at)
			require.NoError(t, err)
		}
	}
	tests := []struct {
		name            string
		setup           func()
		wantCnt         int
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name: "nada-todo",
		},
		{
			name: "close-2",
			setup: func() {
				createWith(2, -10*time.Second, PendingStatus)
				createWith(1, 10*time.Second, IssuedStatus)
				createWith(1, 10*time.Second, PendingStatus)
			},
			wantCnt: 2,
		},
		{
			name: "close-zero",
			setup: func() {
				createWith(2, 10*time.Second, PendingStatus)
				createWith(1, 10*time.Second, IssuedStatus)
			},
			wantCnt: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			// start with no tokens in the db.
			_, err := rw.Exec(ctx, "delete from auth_token", nil)
			require.NoError(err)
			_, err = rw.Exec(ctx, "delete from auth_account", nil)
			require.NoError(err)

			if tt.setup != nil {
				tt.setup()
			}
			tokensClosed, err := repo.CloseExpiredPendingTokens(ctx)
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Equal(0, tokensClosed)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "wanted %s and got: %s", tt.wantErrMatch.Code, err.Error())
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantCnt, tokensClosed)
		})
	}
}

func Test_listDeletedIds(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iamRepo)
	at := TestAuthToken(t, conn, kms, org.GetPublicId())
	at.Token = ""
	at.KeyId = ""
	repo, err := NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)

	// Expect no entries at the start
	deletedIds, ttime, err := repo.listDeletedIds(ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(t, err)
	require.Empty(t, deletedIds)
	// Transaction timestamp should be within ~10 seconds of now
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))

	// Delete an auth token
	_, err = repo.DeleteAuthToken(ctx, at.GetPublicId())
	require.NoError(t, err)

	// Expect a single entry
	deletedIds, ttime, err = repo.listDeletedIds(ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(t, err)
	require.Equal(t, []string{at.GetPublicId()}, deletedIds)
	// Transaction timestamp should be within ~10 seconds of now
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))

	// Try again with the time set to now, expect no entries
	deletedIds, ttime, err = repo.listDeletedIds(ctx, time.Now())
	require.NoError(t, err)
	require.Empty(t, deletedIds)
	// Transaction timestamp should be within ~10 seconds of now
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))
}

func Test_estimatedCount(t *testing.T) {
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

	// Check total entries at start, expect 0
	numItems, err := repo.estimatedCount(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, numItems)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iamRepo)
	// Create an auth token, expect 1 entry
	at := TestAuthToken(t, conn, kms, org.GetPublicId())
	at.Token = ""
	at.KeyId = ""

	// Run analyze to update estimate
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)
	numItems, err = repo.estimatedCount(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, numItems)

	// Delete the auth token, expect 0 again
	_, err = repo.DeleteAuthToken(ctx, at.GetPublicId())
	require.NoError(t, err)

	// Run analyze to update estimate
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)
	numItems, err = repo.estimatedCount(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, numItems)
}
