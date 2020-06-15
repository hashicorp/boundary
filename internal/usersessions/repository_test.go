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
	defer func() {
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	}()

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
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	}()
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	var tests = []struct {
		name      string
		in        *Session
		opts      []Option
		want      *Session
		wantIsErr error
	}{
		{
			name:      "nil-catalog",
			wantIsErr: db.ErrNilParameter,
		},
		{
			name:      "nil-embedded-catalog",
			in:        &Session{},
			wantIsErr: db.ErrNilParameter,
		},
		{
			name: "valid-no-options",
			in: &Session{
				Session: &store.Session{},
			},
			want: &Session{
				Session: &store.Session{},
			},
		},
		{
			name: "valid-with-name",
			in: &Session{
				Session: &store.Session{},
			},
			want: &Session{
				Session: &store.Session{},
			},
		},
		{
			name: "valid-with-description",
			in: &Session{
				Session: &store.Session{},
			},
			want: &Session{
				Session: &store.Session{},
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
			assert.Equal(got.CreateTime, got.UpdateTime)
		})
	}

	t.Run("invalid-duplicate-names", func(t *testing.T) {
		assert := assert.New(t)
		repo, err := NewRepository(rw, rw, wrapper)
		assert.NoError(err)
		assert.NotNil(repo)

		_, prj := iam.TestScopes(t, conn)
		in := &Session{
			Session: &store.Session{
				IamScopeId: prj.GetPublicId(),
			},
		}

		got, err := repo.CreateSession(context.Background(), in)
		assert.NoError(err)
		assert.NotNil(got)
		assertPublicId(t, SessionPrefix, got.PublicId)
		assert.NotSame(in, got)
		assert.Equal(got.CreateTime, got.UpdateTime)

		got2, err := repo.CreateSession(context.Background(), in)
		assert.Truef(errors.Is(err, db.ErrNotUnique), "want err: %v got: %v", db.ErrNotUnique, err)
		assert.Nil(got2)
	})

	t.Run("valid-duplicate-names-diff-scopes", func(t *testing.T) {
		assert := assert.New(t)
		repo, err := NewRepository(rw, rw, wrapper)
		assert.NoError(err)
		assert.NotNil(repo)

		org, prj := iam.TestScopes(t, conn)
		in := &Session{
			Session: &store.Session{},
		}
		in2 := in.clone()

		in.IamScopeId = prj.GetPublicId()
		got, err := repo.CreateSession(context.Background(), in)
		assert.NoError(err)
		assert.NotNil(got)
		assertPublicId(t, SessionPrefix, got.PublicId)
		assert.NotSame(in, got)
		assert.Equal(got.CreateTime, got.UpdateTime)

		in2.IamScopeId = org.GetPublicId()
		got2, err := repo.CreateSession(context.Background(), in2)
		assert.NoError(err)
		assert.NotNil(got2)
		assertPublicId(t, SessionPrefix, got2.PublicId)
		assert.NotSame(in2, got2)
		assert.Equal(got2.CreateTime, got2.UpdateTime)
	})
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
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	}()

	sess := testSession(t, conn)
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

			switch {
			case tt.want == nil:
				assert.Nil(got)
			case tt.want != nil:
				assert.NotNil(got)
				assert.Equal(got, tt.want)
			}
		})
	}
}

func TestRepository_DeleteSession(t *testing.T) {
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	}()

	cat := testSession(t, conn)
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
			id:   cat.GetPublicId(),
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
