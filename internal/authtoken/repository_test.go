package authtoken

import (
	"context"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/google/go-cmp/cmp"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/watchtower/internal/auth/password"
	iamStore "github.com/hashicorp/watchtower/internal/iam/store"
	"github.com/hashicorp/watchtower/internal/oplog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/hashicorp/watchtower/internal/authtoken/store"
	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/iam"
)

func TestRepository_New(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	type args struct {
		r       db.Reader
		w       db.Writer
		wrapper wrapping.Wrapper
		opts    []Option
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
				r:       rw,
				w:       rw,
				wrapper: wrapper,
			},
			want: &Repository{
				reader:       rw,
				writer:       rw,
				wrapper:      wrapper,
				defaultLimit: db.DefaultLimit,
			},
		},
		{
			name: "valid new limit",
			args: args{
				r:       rw,
				w:       rw,
				wrapper: wrapper,
				opts:    []Option{WithLimit(5)},
			},
			want: &Repository{
				reader:       rw,
				writer:       rw,
				wrapper:      wrapper,
				defaultLimit: 5,
			},
		},
		{
			name: "nil-reader",
			args: args{
				r:       nil,
				w:       rw,
				wrapper: wrapper,
			},
			want:      nil,
			wantIsErr: db.ErrNilParameter,
		},
		{
			name: "nil-writer",
			args: args{
				r:       rw,
				w:       nil,
				wrapper: wrapper,
			},
			want:      nil,
			wantIsErr: db.ErrNilParameter,
		},
		{
			name: "nil-wrapper",
			args: args{
				r:       rw,
				w:       rw,
				wrapper: nil,
			},
			want:      nil,
			wantIsErr: db.ErrNilParameter,
		},
		{
			name: "all-nils",
			args: args{
				r:       nil,
				w:       nil,
				wrapper: nil,
			},
			want:      nil,
			wantIsErr: db.ErrNilParameter,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			got, err := NewRepository(tt.args.r, tt.args.w, tt.args.wrapper, tt.args.opts...)
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

	org1, _ := iam.TestScopes(t, conn)
	am := password.TestAuthMethods(t, conn, org1.GetPublicId(), 1)[0]
	aAcct := password.TestAccounts(t, conn, am.GetPublicId(), 1)[0]

	iamRepo, err := iam.NewRepository(rw, rw, wrapper)
	require.NoError(t, err)
	u1, err := iamRepo.LookupUserWithLogin(context.Background(), aAcct.GetPublicId(), iam.WithAutoVivify(true))
	require.NoError(t, err)

	org2, _ := iam.TestScopes(t, conn)
	u2 := iam.TestUser(t, conn, org2.GetPublicId())

	var tests = []struct {
		name       string
		iamUserId  string
		authAcctId string
		want       *AuthToken
		wantErr    bool
	}{
		{
			name:       "valid",
			iamUserId:  u1.GetPublicId(),
			authAcctId: aAcct.GetPublicId(),
			want: &AuthToken{
				AuthToken: &store.AuthToken{
					AuthAccountId: aAcct.GetPublicId(),
				},
			},
		},
		{
			name:       "unconnected-authaccount-user",
			iamUserId:  u2.GetPublicId(),
			authAcctId: aAcct.GetPublicId(),
			wantErr:    true,
		},
		{
			name:      "no-authacctid",
			iamUserId: u1.GetPublicId(),
			wantErr:   true,
		},
		{
			name:       "no-userid",
			authAcctId: aAcct.GetPublicId(),
			wantErr:    true,
		},
		{
			name:       "invalid-authacctid",
			iamUserId:  u1.GetPublicId(),
			authAcctId: "this_is_invalid",
			wantErr:    true,
		},
		{
			name:       "invalid-userid",
			iamUserId:  "this_is_invalid",
			authAcctId: aAcct.GetPublicId(),
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(rw, rw, wrapper)
			require.NoError(err)
			require.NotNil(repo)
			got, err := repo.CreateAuthToken(context.Background(), tt.iamUserId, tt.authAcctId)
			if tt.wantErr {
				assert.Error(err)
				assert.Nil(got)
				return
			}
			require.NoError(err, "Got error for CreateAuthToken(ctx, %v, %v)", tt.iamUserId, tt.authAcctId)
			assert.NotNil(got)
			db.AssertPublicId(t, AuthTokenPrefix, got.PublicId)
			assert.Equal(tt.authAcctId, got.GetAuthAccountId())
			assert.Equal(got.CreateTime, got.UpdateTime)
			assert.Equal(got.CreateTime, got.ApproximateLastAccessTime)
			assert.NoError(db.TestVerifyOplog(t, rw, got.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_CREATE)))
		})
	}
}

func TestRepository_LookupAuthToken(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	org, _ := iam.TestScopes(t, conn)
	at := TestAuthToken(t, conn, wrapper, org.GetPublicId())
	at.Token = ""
	at.CtToken = nil

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
			wantErr: db.ErrInvalidParameter,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(rw, rw, wrapper)
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

	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo, err := NewRepository(rw, rw, wrapper)
	require.NoError(t, err)
	require.NotNil(t, repo)

	org, _ := iam.TestScopes(t, conn)
	at := TestAuthToken(t, conn, wrapper, org.GetPublicId())
	atToken := at.GetToken()
	at.Token = ""
	at.CtToken = nil
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
			wantErr: db.ErrInvalidParameter,
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

			assert.NoError(db.TestVerifyOplog(t, rw, got.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_UPDATE)))

			got3, err := repo.ValidateToken(context.Background(), tt.id, tt.token)
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
	repo, err := NewRepository(rw, rw, wrapper)
	require.NoError(t, err)
	require.NotNil(t, repo)

	org, _ := iam.TestScopes(t, conn)
	baseAT := TestAuthToken(t, conn, wrapper, org.GetPublicId())
	baseAT.GetAuthAccountId()
	aAcct := &iam.AuthAccount{AuthAccount: &iamStore.AuthAccount{PublicId: baseAT.GetAuthAccountId()}}
	require.NoError(t, rw.LookupByPublicId(context.Background(), aAcct))
	iamUserId := aAcct.GetIamUserId()

	defaultStaleTime := maxStaleness
	defaultExpireDuration := maxTokenDuration

	var tests = []struct {
		name               string
		staleDuration      time.Duration
		expirationDuration time.Duration
		wantReturned       bool
	}{
		{
			name:               "not-stale-or-expired",
			staleDuration:      maxStaleness,
			expirationDuration: maxTokenDuration,
			wantReturned:       true,
		},
		{
			name:               "stale",
			staleDuration:      0,
			expirationDuration: maxTokenDuration,
			wantReturned:       false,
		},
		{
			name:               "expired",
			staleDuration:      maxStaleness,
			expirationDuration: 0,
			wantReturned:       false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			maxStaleness = tt.staleDuration
			maxTokenDuration = tt.expirationDuration

			ctx := context.Background()
			at, err := repo.CreateAuthToken(ctx, iamUserId, baseAT.GetAuthAccountId())
			require.NoError(err)

			got, err := repo.ValidateToken(ctx, at.GetPublicId(), at.GetToken())
			require.NoError(err)

			if tt.wantReturned {
				assert.NotNil(got)
			} else {
				assert.NoError(db.TestVerifyOplog(t, rw, at.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_DELETE)))
				assert.Nil(got)
			}

			// reset the system default params
			maxStaleness = defaultStaleTime
			maxTokenDuration = defaultExpireDuration
		})
	}
}

func TestRepository_DeleteAuthToken(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	org, _ := iam.TestScopes(t, conn)
	at := TestAuthToken(t, conn, wrapper, org.GetPublicId())
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
			wantErr: db.ErrInvalidParameter,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(rw, rw, wrapper)
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
				assert.NoError(db.TestVerifyOplog(t, rw, tt.id, db.WithOperation(oplog.OpType_OP_TYPE_DELETE)))
			}
		})
	}
}

func TestRepository_ListAuthTokens(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	org, _ := iam.TestScopes(t, conn)
	at1 := TestAuthToken(t, conn, wrapper, org.GetPublicId())
	at1.Token = ""
	at2 := TestAuthToken(t, conn, wrapper, org.GetPublicId())
	at2.Token = ""
	at3 := TestAuthToken(t, conn, wrapper, org.GetPublicId())
	at3.Token = ""

	emptyOrg, _ := iam.TestScopes(t, conn)

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
			wantErr: db.ErrInvalidParameter,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(rw, rw, wrapper)
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
