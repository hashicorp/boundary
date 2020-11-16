package authtoken

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"

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

	var tests = []struct {
		name      string
		args      args
		want      *Repository
		wantIsErr error
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
			want:      nil,
			wantIsErr: errors.ErrInvalidParameter,
		},
		{
			name: "nil-writer",
			args: args{
				r:   rw,
				w:   nil,
				kms: kmsCache,
			},
			want:      nil,
			wantIsErr: errors.ErrInvalidParameter,
		},
		{
			name: "nil-kms",
			args: args{
				r:   rw,
				w:   rw,
				kms: nil,
			},
			want:      nil,
			wantIsErr: errors.ErrInvalidParameter,
		},
		{
			name: "all-nils",
			args: args{
				r:   nil,
				w:   nil,
				kms: nil,
			},
			want:      nil,
			wantIsErr: errors.ErrInvalidParameter,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			got, err := NewRepository(tt.args.r, tt.args.w, tt.args.kms, tt.args.opts...)
			if tt.wantIsErr != nil {
				assert.Truef(errors.Is(err, tt.wantIsErr), "want err: %q got: %q", tt.wantIsErr, err)
				assert.Nil(got)
				return
			}
			assert.NoError(err)
			assert.NotNil(got)
			assert.Equal(tt.want, got)
		})
	}
}

func TestRepository_CreateAuthToken(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	repo := iam.TestRepo(t, conn, wrapper)

	org1, _ := iam.TestScopes(t, repo)
	am := password.TestAuthMethods(t, conn, org1.GetPublicId(), 1)[0]
	aAcct := password.TestAccounts(t, conn, am.GetPublicId(), 1)[0]

	iamRepo, err := iam.NewRepository(rw, rw, kms)
	require.NoError(t, err)
	u1, err := iamRepo.LookupUserWithLogin(context.Background(), aAcct.GetPublicId(), iam.WithAutoVivify(true))
	require.NoError(t, err)

	org2, _ := iam.TestScopes(t, repo)
	u2 := iam.TestUser(t, repo, org2.GetPublicId())

	var tests = []struct {
		name       string
		iamUser    *iam.User
		authAcctId string
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
			repo, err := NewRepository(rw, rw, kms)
			require.NoError(err)
			require.NotNil(repo)
			got, err := repo.CreateAuthToken(context.Background(), tt.iamUser, tt.authAcctId)
			if tt.wantErr {
				assert.Error(err)
				assert.Nil(got)
				return
			}
			require.NoError(err, "Got error for CreateAuthToken(ctx, %v, %v)", tt.iamUser, tt.authAcctId)
			assert.NotNil(got)
			db.AssertPublicId(t, AuthTokenPrefix, got.PublicId)
			assert.Equal(tt.authAcctId, got.GetAuthAccountId())
			assert.Equal(got.CreateTime, got.UpdateTime)
			assert.Equal(got.CreateTime, got.ApproximateLastAccessTime)
			// We should find no oplog since tokens are not replicated, so they don't need oplog entries.
			assert.Error(db.TestVerifyOplog(t, rw, got.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_CREATE)))
		})
	}
}

func TestRepository_LookupAuthToken(t *testing.T) {
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

	badId, err := newAuthTokenId()
	require.NoError(t, err)
	require.NotNil(t, badId)

	var tests = []struct {
		name    string
		id      string
		want    *AuthToken
		wantErr error
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
			name:    "bad-public-id",
			id:      "",
			want:    nil,
			wantErr: errors.ErrInvalidParameter,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(rw, rw, kms)
			require.NoError(err)
			require.NotNil(repo)

			got, err := repo.LookupAuthToken(context.Background(), tt.id)
			if tt.wantErr != nil {
				assert.Truef(errors.Is(err, tt.wantErr), "want err: %q got: %q", tt.wantErr, err)
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
			wantGoTimeExpr, err := ptypes.Timestamp(tt.want.AuthToken.GetExpirationTime().Timestamp)
			require.NoError(err)
			gotGoTimeExpr, err := ptypes.Timestamp(got.AuthToken.GetExpirationTime().Timestamp)
			require.NoError(err)
			assert.WithinDuration(wantGoTimeExpr, gotGoTimeExpr, time.Millisecond)
			tt.want.AuthToken.ExpirationTime = got.AuthToken.ExpirationTime
			assert.Empty(cmp.Diff(tt.want.AuthToken, got.AuthToken, protocmp.Transform()))
		})
	}
}

func TestRepository_ValidateToken(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	lastAccessedUpdateDuration = 0
	timeSkew = 20 * time.Millisecond

	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	repo, err := NewRepository(rw, rw, kms)

	require.NoError(t, err)
	require.NotNil(t, repo)

	org, _ := iam.TestScopes(t, iamRepo)
	at := TestAuthToken(t, conn, kms, org.GetPublicId())
	atToken := at.GetToken()
	at.Token = ""
	at.CtToken = nil
	at.KeyId = ""
	atTime, err := ptypes.Timestamp(at.GetApproximateLastAccessTime().GetTimestamp())
	require.NoError(t, err)
	require.NotNil(t, atTime)

	badId, err := newAuthTokenId()
	require.NoError(t, err)
	require.NotNil(t, badId)

	badToken, err := newAuthToken()
	require.NoError(t, err)
	require.NotNil(t, badToken)

	var tests = []struct {
		name    string
		id      string
		token   string
		want    *AuthToken
		wantErr error
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
			token: badToken,
			want:  nil,
		},
		{
			name:    "empty-token",
			id:      at.GetPublicId(),
			token:   "",
			want:    nil,
			wantErr: errors.ErrInvalidParameter,
		},
		{
			name:    "mismatched-token",
			id:      at.GetPublicId(),
			token:   badToken,
			want:    nil,
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := repo.ValidateToken(context.Background(), tt.id, tt.token)

			if tt.wantErr != nil {
				assert.Truef(errors.Is(err, tt.wantErr), "want err: %q got: %q", tt.wantErr, err)
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
			wantGoTimeExpr, err := ptypes.Timestamp(tt.want.AuthToken.GetExpirationTime().Timestamp)
			require.NoError(err)
			gotGoTimeExpr, err := ptypes.Timestamp(got.AuthToken.GetExpirationTime().Timestamp)
			require.NoError(err)
			assert.WithinDuration(wantGoTimeExpr, gotGoTimeExpr, time.Millisecond)
			tt.want.AuthToken.ExpirationTime = got.AuthToken.ExpirationTime
			assert.Empty(cmp.Diff(tt.want.AuthToken, got.AuthToken, protocmp.Transform()))

			// preTime1 should be the value prior to the ValidateToken was called so it should equal creation time
			preTime1, err := ptypes.Timestamp(got.GetApproximateLastAccessTime().GetTimestamp())
			require.NoError(err)
			assert.True(preTime1.Equal(atTime), "Create time %q doesn't match the time from the first call to MaybeUpdateLastAccesssed: %q.", atTime, preTime1)

			// Enable the duration which limits how frequently a token's approximate last accessed time can be updated
			// so the next call doesn't cause the last accessed time to be updated.
			lastAccessedUpdateDuration = 1 * time.Hour

			got2, err := repo.ValidateToken(context.Background(), tt.id, tt.token)
			assert.NoError(err)
			preTime2, err := ptypes.Timestamp(got2.GetApproximateLastAccessTime().GetTimestamp())
			require.NoError(err)
			assert.True(preTime2.After(preTime1), "First updated time %q was not after the creation time %q", preTime2, preTime1)

			// We should find no oplog since tokens are not replicated, so they don't need oplog entries.
			assert.Error(db.TestVerifyOplog(t, rw, got.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_UPDATE)))

			got3, err := repo.ValidateToken(context.Background(), tt.id, tt.token)
			require.NoError(err)
			preTime3, err := ptypes.Timestamp(got3.GetApproximateLastAccessTime().GetTimestamp())
			require.NoError(err)
			assert.True(preTime3.Equal(preTime2), "The 3rd timestamp %q was not equal to the second time %q", preTime3, preTime2)
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

	var tests = []struct {
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

			timeSkew = 20 * time.Millisecond

			repo, err := NewRepository(rw, rw, kms,
				WithTokenTimeToLiveDuration(tt.expirationDuration),
				WithTokenTimeToStaleDuration(tt.staleDuration))
			require.NoError(err)
			require.NotNil(repo)

			ctx := context.Background()
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
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	repo := iam.TestRepo(t, conn, wrapper)
	org, _ := iam.TestScopes(t, repo)
	at := TestAuthToken(t, conn, kms, org.GetPublicId())
	badId, err := newAuthTokenId()
	require.NoError(t, err)
	require.NotNil(t, badId)

	var tests = []struct {
		name    string
		id      string
		want    int
		wantErr error
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
			name:    "empty-public-id",
			id:      "",
			want:    0,
			wantErr: errors.ErrInvalidParameter,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(rw, rw, kms)
			require.NoError(err)
			require.NotNil(repo)

			got, err := repo.DeleteAuthToken(context.Background(), tt.id)
			if tt.wantErr != nil {
				assert.Truef(errors.Is(err, tt.wantErr), "want err: %q got: %q", tt.wantErr, err)
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

	var tests = []struct {
		name    string
		orgId   string
		want    []*AuthToken
		wantErr error
	}{
		{
			name:  "populated",
			orgId: org.GetPublicId(),
			want:  []*AuthToken{at1, at2, at3},
		},
		{
			name:  "empty",
			orgId: emptyOrg.GetPublicId(),
			want:  []*AuthToken{},
		},
		{
			name:    "empty-org-id",
			orgId:   "",
			want:    nil,
			wantErr: errors.ErrInvalidParameter,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(rw, rw, kms)
			require.NoError(err)
			require.NotNil(repo)

			got, err := repo.ListAuthTokens(context.Background(), tt.orgId)
			if tt.wantErr != nil {
				assert.Truef(errors.Is(err, tt.wantErr), "want err: %q got: %q", tt.wantErr, err)
				return
			}
			assert.NoError(err)
			sort.Slice(tt.want, func(i, j int) bool { return tt.want[i].PublicId < tt.want[j].PublicId })
			sort.Slice(got, func(i, j int) bool { return got[i].PublicId < got[j].PublicId })
			assert.Empty(cmp.Diff(tt.want, got, protocmp.Transform()), "row count")
		})
	}
}
