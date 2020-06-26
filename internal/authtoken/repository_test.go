package authtoken

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/google/go-cmp/cmp"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/watchtower/internal/oplog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/hashicorp/watchtower/internal/authtoken/store"
	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/iam"
)

func TestRepository_New(t *testing.T) {
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	})

	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	type args struct {
		r       db.Reader
		w       db.Writer
		wrapper wrapping.Wrapper
	}

	var tests = []struct {
		name      string
		args      args
		want      *Repository
		wantIsErr error
	}{
		{
			name: "valid",
			args: args{
				r:       rw,
				w:       rw,
				wrapper: wrapper,
			},
			want: &Repository{
				reader:  rw,
				writer:  rw,
				wrapper: wrapper,
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
			got, err := NewRepository(tt.args.r, tt.args.w, tt.args.wrapper)
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
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	t.Cleanup(func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	})
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	org1, _ := iam.TestScopes(t, conn)
	u1 := iam.TestUser(t, conn, org1.GetPublicId())
	amId1 := setupAuthMethod(t, conn, org1.GetPublicId())

	org2, _ := iam.TestScopes(t, conn)
	u2 := iam.TestUser(t, conn, org2.GetPublicId())
	amId2 := setupAuthMethod(t, conn, org2.GetPublicId())

	var tests = []struct {
		name    string
		in      *AuthToken
		opts    []Option
		want    *AuthToken
		wantErr bool
	}{
		{
			name: "valid-no-options",
			in: &AuthToken{
				AuthToken: &store.AuthToken{
					ScopeId:      org1.GetPublicId(),
					IamUserId:    u1.GetPublicId(),
					AuthMethodId: amId1,
				},
			},
			want: &AuthToken{
				AuthToken: &store.AuthToken{
					ScopeId:      org1.GetPublicId(),
					IamUserId:    u1.GetPublicId(),
					AuthMethodId: amId1,
				},
			},
		},
		{
			name:    "nil-authtoken",
			wantErr: true,
		},
		{
			name:    "nil-embedded-authtoken",
			in:      &AuthToken{},
			wantErr: true,
		},
		{
			name: "unmatched-authtoken-user-scopes",
			in: &AuthToken{
				AuthToken: &store.AuthToken{
					ScopeId:      org1.GetPublicId(),
					IamUserId:    u2.GetPublicId(),
					AuthMethodId: amId1,
				}},
			wantErr: true,
		},
		{
			name: "unmatched-authtoken-authmethod-scopes",
			in: &AuthToken{
				AuthToken: &store.AuthToken{
					ScopeId:      org1.GetPublicId(),
					IamUserId:    u1.GetPublicId(),
					AuthMethodId: amId2,
				}},
			wantErr: true,
		},
		{
			name: "no-scopeid",
			in: &AuthToken{
				AuthToken: &store.AuthToken{
					IamUserId:    u1.GetPublicId(),
					AuthMethodId: amId1,
				},
			},
			wantErr: true,
		},
		{
			name: "no-authmethodid",
			in: &AuthToken{
				AuthToken: &store.AuthToken{
					ScopeId:   org1.GetPublicId(),
					IamUserId: u1.GetPublicId(),
				},
			},
			wantErr: true,
		},
		{
			name: "no-userid",
			in: &AuthToken{
				AuthToken: &store.AuthToken{
					ScopeId:      org1.GetPublicId(),
					AuthMethodId: amId1,
				},
			},
			wantErr: true,
		},
		{
			name: "invalid-scopeid",
			in: &AuthToken{
				AuthToken: &store.AuthToken{
					IamUserId:    u1.GetPublicId(),
					AuthMethodId: amId1,
					ScopeId:      "this_is_invalid",
				},
			},
			wantErr: true,
		},
		{
			name: "invalid-authmethodid",
			in: &AuthToken{
				AuthToken: &store.AuthToken{
					ScopeId:      org1.GetPublicId(),
					IamUserId:    u1.GetPublicId(),
					AuthMethodId: "this_is_invalid",
				},
			},
			wantErr: true,
		},
		{
			name: "invalid-userid",
			in: &AuthToken{
				AuthToken: &store.AuthToken{
					ScopeId:      org1.GetPublicId(),
					AuthMethodId: amId1,
					IamUserId:    "this_is_invalid",
				},
			},
			wantErr: true,
		},
		{
			name: "token-specified",
			in: &AuthToken{
				AuthToken: &store.AuthToken{
					ScopeId:      org1.GetPublicId(),
					IamUserId:    u1.GetPublicId(),
					AuthMethodId: amId1,
					Token:        "anything_here_should_result_in_an_error",
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(rw, rw, wrapper)
			require.NoError(err)
			require.NotNil(repo)
			got, err := repo.CreateAuthToken(context.Background(), tt.in, tt.opts...)
			if tt.wantErr {
				assert.Error(err)
				assert.Nil(got)
				return
			}
			require.NoError(err, "Got error for CreateAuthToken(ctx, %v, %v)", tt.in, tt.opts)
			assert.Empty(tt.in.PublicId)
			assert.NotNil(got)
			db.AssertPublicId(t, AuthTokenPrefix, got.PublicId)
			assert.NotSame(tt.in, got)
			assert.Equal(got.CreateTime, got.UpdateTime)
			assert.Equal(got.CreateTime, got.ApproximateLastAccessTime)
			assert.NoError(db.TestVerifyOplog(t, rw, got.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_CREATE)))
		})
	}
}

func TestRepository_LookupAuthToken(t *testing.T) {
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	t.Cleanup(func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	})

	at := testAuthToken(t, conn)
	at.Token = ""
	at.CtToken = nil

	badId, err := newAuthTokenId()
	require.NoError(t, err)
	require.NotNil(t, badId)

	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

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
			assert.Empty(cmp.Diff(tt.want.AuthToken, got.AuthToken, protocmp.Transform()))
		})
	}
}

func TestRepository_UpdateLastAccessed(t *testing.T) {
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	t.Cleanup(func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	})

	lastUsedUpdateDuration = 0

	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo, err := NewRepository(rw, rw, wrapper)
	require.NoError(t, err)
	require.NotNil(t, repo)

	tmp := testAuthToken(t, conn)
	// Create a new auth token using the repo's wrapper
	at, err := NewAuthToken(tmp.GetScopeId(), tmp.GetIamUserId(), tmp.GetAuthMethodId())
	require.NoError(t, err)
	at, err = repo.CreateAuthToken(context.Background(), at)
	require.NoError(t, err)
	require.NotNil(t, at)
	atToken := at.GetToken()
	at.Token = ""
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
			name:    "doesnt-exist",
			id:      badId,
			token:   badToken,
			want:    nil,
			wantErr: db.ErrRecordNotFound,
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
			wantErr: db.ErrInvalidParameter,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := repo.MaybeUpdateLastAccessed(context.Background(), tt.id, tt.token)
			if tt.wantErr != nil {
				assert.Truef(errors.Is(err, tt.wantErr), "want err: %q got: %q", tt.wantErr, err)
				return
			}
			assert.NoError(err)
			if got == nil {
				assert.Nil(tt.want, "Got nil but wanted %v", tt.want.AuthToken)
				// No need to compare updated time if we didn't get an initial auth token to compare against.
				return
			}
			require.NotNil(tt.want, "Got %v but wanted nil", got)
			assert.Empty(cmp.Diff(tt.want.AuthToken, got.AuthToken, protocmp.Transform()))
			// preTime1 should be the value prior to the MaybeUpdateLastAccessed was called so it should equal creation time
			preTime1, err := ptypes.Timestamp(got.GetApproximateLastAccessTime().GetTimestamp())
			require.NoError(err)
			assert.True(preTime1.Equal(atTime), "Create time %q doesn't match the time from the first call to MaybeUpdateLastAccesssed: %q.", atTime, preTime1)

			// Enable the duration which limits how frequently a token's approximate last accessed time can be updated
			// so the next call doesn't cause the last accessed time to be updated.
			lastUsedUpdateDuration = 1 * time.Hour

			got2, err := repo.MaybeUpdateLastAccessed(context.Background(), tt.id, tt.token)
			assert.NoError(err)
			preTime2, err := ptypes.Timestamp(got2.GetApproximateLastAccessTime().GetTimestamp())
			require.NoError(err)
			assert.True(preTime2.After(preTime1), "First updated time %q was not after the creation time %q", preTime2, preTime1)

			assert.NoError(db.TestVerifyOplog(t, rw, got.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_UPDATE)))

			got3, err := repo.MaybeUpdateLastAccessed(context.Background(), tt.id, tt.token)
			preTime3, err := ptypes.Timestamp(got3.GetApproximateLastAccessTime().GetTimestamp())
			require.NoError(err)
			assert.True(preTime3.Equal(preTime2), "The 3rd timestamp %q was not equal to the second time %q", preTime3, preTime2)
		})
	}
}

func TestRepository_DeleteAuthToken(t *testing.T) {
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	t.Cleanup(func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	})

	at := testAuthToken(t, conn)
	badId, err := newAuthTokenId()
	require.NoError(t, err)
	require.NotNil(t, badId)

	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

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
