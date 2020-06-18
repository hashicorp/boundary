package usersessions

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/golang/protobuf/ptypes"
	"github.com/google/go-cmp/cmp"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/iam"
	"github.com/hashicorp/watchtower/internal/usersessions/store"
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

func TestRepository_CreateSession(t *testing.T) {
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
	org2, _ := iam.TestScopes(t, conn)
	u2 := iam.TestUser(t, conn, org2.GetPublicId())

	var tests = []struct {
		name      string
		in        *Session
		opts      []Option
		want      *Session
		wantIsErr error
	}{
		{
			name:      "nil-session",
			wantIsErr: db.ErrNilParameter,
		},
		{
			name:      "nil-embedded-session",
			in:        &Session{},
			wantIsErr: db.ErrNilParameter,
		},
		{
			name: "valid-no-options",
			in: &Session{
				Session: &store.Session{
					IamScopeId:   org1.GetPublicId(),
					IamUserId:    u1.GetPublicId(),
					AuthMethodId: "something",
				},
			},
			want: &Session{
				Session: &store.Session{
					IamScopeId:   org1.GetPublicId(),
					IamUserId:    u1.GetPublicId(),
					AuthMethodId: "something",
				},
			},
		},
		{
			name: "scope-mismatch-with-iam-user",
			in: &Session{
				Session: &store.Session{
					IamScopeId:   org1.GetPublicId(),
					IamUserId:    u2.GetPublicId(),
					AuthMethodId: "something",
				},
			},
			wantIsErr: db.ErrNilParameter,
		},
		// TODO: Test scope mismatch with auth method.
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			repo, err := NewRepository(rw, rw, wrapper)
			assert.NoError(err)
			assert.NotNil(repo)
			got, err := repo.CreateSession(context.Background(), tt.in, tt.opts...)
			if tt.wantIsErr != nil {
				assert.Truef(errors.Is(err, tt.wantIsErr), "want err: %q got: %q", tt.wantIsErr, err)
				assert.Nil(got)
				return
			}
			assert.NoError(err)
			assert.Empty(tt.in.PublicId)
			assert.NotNil(got)
			assertPublicId(t, SessionPrefix, got.PublicId)
			assert.NotSame(tt.in, got)
			assert.Equal(got.CreateTime, got.LastUsedTime)
		})
	}
}

func assertPublicId(t *testing.T, prefix, actual string) {
	t.Helper()
	assert.NotEmpty(t, actual)
	parts := strings.Split(actual, "_")
	assert.Equalf(t, 2, len(parts), "want one '_' in PublicId, got multiple in %q", actual)
	assert.Equalf(t, prefix, parts[0], "PublicId want prefix: %q, got: %q in %q", prefix, parts[0], actual)
}

func TestRepository_LookupSession(t *testing.T) {
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	t.Cleanup(func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	})

	sess := testSession(t, conn)
	sess.Token = ""

	badId, err := newSessionId()
	assert.NoError(t, err)
	assert.NotNil(t, badId)

	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	var tests = []struct {
		name    string
		id      string
		want    *Session
		wantErr error
	}{
		{
			name: "found",
			id:   sess.GetPublicId(),
			want: sess,
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

			got, err := repo.LookupSession(context.Background(), tt.id)
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

	sess := testSession(t, conn)
	sessToken := sess.GetToken()
	sess.Token = ""
	badToken, err := newSessionToken()
	assert.NoError(err)
	assert.NotNil(badToken)

	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	var tests = []struct {
		name    string
		token   string
		want    *Session
		wantErr error
	}{
		{
			name:  "exists",
			token: sessToken,
			want:  sess,
		},
		{
			name:  "doesnt-exist",
			token: badToken,
			want:  nil,
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
				// No need to compare updated time if we didn't get an initial session to compare against.
				return
			}
			assert.Empty(cmp.Diff(tt.want.Session, got.Session, protocmp.Transform()))

			got2, err := repo.UpdateLastUsed(context.Background(), tt.token)
			if tt.wantErr != nil {
				assert.Truef(errors.Is(err, tt.wantErr), "want err: %q got: %q", tt.wantErr, err)
				return
			}
			assert.NoError(err)
			time1, err := ptypes.Timestamp(got.GetLastUsedTime().GetTimestamp())
			require.NoError(err)
			time2, err := ptypes.Timestamp(got2.GetLastUsedTime().GetTimestamp())
			require.NoError(err)
			assert.True(time2.After(time1), "Second last update time %q was not after first time %q", time2, time1)
		})
	}
}

func TestRepository_DeleteSession(t *testing.T) {
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	t.Cleanup(func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	})

	sess := testSession(t, conn)
	badId, err := newSessionId()
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
			id:   sess.GetPublicId(),
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

			got, err := repo.DeleteSession(context.Background(), tt.id)
			if tt.wantErr != nil {
				assert.Truef(errors.Is(err, tt.wantErr), "want err: %q got: %q", tt.wantErr, err)
				return
			}
			assert.NoError(err)
			assert.Equal(tt.want, got, "row count")
		})
	}
}
