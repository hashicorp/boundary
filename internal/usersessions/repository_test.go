package usersessions

import (
	"context"
	"errors"
	"strings"
	"testing"

	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/stretchr/testify/assert"

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

	org, _ := iam.TestScopes(t, conn)
	u := iam.TestUser(t, conn, org.GetPublicId())

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
					IamScopeId:   org.GetPublicId(),
					IamUserId:    u.GetPublicId(),
					AuthMethodId: "something",
				},
			},
			want: &Session{
				Session: &store.Session{
					IamScopeId:   org.GetPublicId(),
					IamUserId:    u.GetPublicId(),
					AuthMethodId: "something",
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			repo, err := NewRepository(rw, rw, wrapper)
			assert.NoError(err)
			assert.NotNil(repo)
			_, prj := iam.TestScopes(t, conn)
			if tt.in != nil && tt.in.Session != nil {
				tt.in.IamScopeId = prj.GetPublicId()
				assert.Empty(tt.in.PublicId)
			}
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
func TestRepository_LookupSessionByToken(t *testing.T) {
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
	assert.NoError(t, err)
	assert.NotNil(t, badToken)

	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	var tests = []struct {
		name    string
		token   string
		want    *Session
		wantErr error
	}{
		{
			name:  "found",
			token: sessToken,
			want:  sess,
		},
		{
			name:  "not-found",
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
			assert := assert.New(t)
			repo, err := NewRepository(rw, rw, wrapper)
			assert.NoError(err)
			assert.NotNil(repo)

			got, err := repo.LookupSessionByToken(context.Background(), tt.token)
			if tt.wantErr != nil {
				assert.Truef(errors.Is(err, tt.wantErr), "want err: %q got: %q", tt.wantErr, err)
				return
			}
			assert.NoError(err)
			assert.Equal(tt.want, got)
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
