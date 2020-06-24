package authtoken

import (
	"context"
	"errors"
	"testing"

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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			repo, err := NewRepository(rw, rw, wrapper)
			assert.NoError(err)
			assert.NotNil(repo)
			got, err := repo.CreateAuthToken(context.Background(), tt.in, tt.opts...)
			if tt.wantErr {
				assert.Error(err)
				assert.Nil(got)
				return
			}
			assert.NoError(err, "Got error for CreateAuthToken(ctx, %v, %v)", tt.in, tt.opts)
			assert.Empty(tt.in.PublicId)
			assert.NotNil(got)
			assertPublicId(t, AuthTokenPublicIdPrefix, got.PublicId)
			assert.NotSame(tt.in, got)
			assert.Equal(got.CreateTime, got.UpdateTime)
			assert.Equal(got.CreateTime, got.LastAccessTime)
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

	badId, err := newAuthTokenId()
	assert.NoError(t, err)
	assert.NotNil(t, badId)

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
			assert := assert.New(t)
			repo, err := NewRepository(rw, rw, wrapper)
			assert.NoError(err)
			assert.NotNil(repo)

			got, err := repo.LookupAuthToken(context.Background(), tt.id)
			if tt.wantErr != nil {
				assert.Truef(errors.Is(err, tt.wantErr), "want err: %q got: %q", tt.wantErr, err)
				return
			}
			assert.NoError(err)
			assert.Equal(tt.want, got)
		})
	}
}

func TestRepository_UpdateLastUsed(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
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
	atToken := at.GetToken()
	at.Token = ""
	badToken, err := newAuthToken()
	assert.NoError(err)
	assert.NotNil(badToken)

	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	var tests = []struct {
		name    string
		token   string
		want    *AuthToken
		wantErr error
	}{
		{
			name:  "exists",
			token: atToken,
			want:  at,
		},
		{
			name:    "doesnt-exist",
			token:   badToken,
			want:    nil,
			wantErr: db.ErrRecordNotFound,
		},
		{
			name:    "bad-token",
			token:   "",
			want:    nil,
			wantErr: db.ErrInvalidParameter,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			repo, err := NewRepository(rw, rw, wrapper)
			assert.NoError(err)
			assert.NotNil(repo)

			got, err := repo.UpdateLastUsed(context.Background(), tt.token)
			if tt.wantErr != nil {
				assert.Truef(errors.Is(err, tt.wantErr), "want err: %q got: %q", tt.wantErr, err)
				return
			}
			assert.NoError(err)
			if tt.want == nil {
				assert.Nil(got)
				// No need to compare updated time if we didn't get an initial auth token to compare against.
				return
			}
			assert.Empty(cmp.Diff(tt.want.AuthToken, got.AuthToken, protocmp.Transform()))

			got2, err := repo.UpdateLastUsed(context.Background(), tt.token)
			if tt.wantErr != nil {
				assert.Truef(errors.Is(err, tt.wantErr), "want err: %q got: %q", tt.wantErr, err)
				return
			}
			assert.NoError(err)
			time1, err := ptypes.Timestamp(got.GetLastAccessTime().GetTimestamp())
			require.NoError(err)
			time2, err := ptypes.Timestamp(got2.GetLastAccessTime().GetTimestamp())
			require.NoError(err)
			assert.True(time2.After(time1), "Second last update time %q was not after first time %q", time2, time1)
			assert.NoError(db.TestVerifyOplog(t, rw, got.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_UPDATE)))
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
	assert.NoError(t, err)
	assert.NotNil(t, badId)

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
			name:    "bad-public-id",
			id:      "",
			want:    0,
			wantErr: db.ErrInvalidParameter,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			repo, err := NewRepository(rw, rw, wrapper)
			assert.NoError(err)
			assert.NotNil(repo)

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
