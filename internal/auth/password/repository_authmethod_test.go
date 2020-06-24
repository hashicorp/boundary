package password

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/hashicorp/watchtower/internal/auth/password/store"
	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_CreateAuthMethod(t *testing.T) {
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

	_, prj := iam.TestScopes(t, conn)

	var tests = []struct {
		name      string
		in        *AuthMethod
		opts      []Option
		want      *AuthMethod
		wantIsErr error
	}{
		{
			name:      "nil-AuthMethod",
			wantIsErr: db.ErrNilParameter,
		},
		{
			name:      "nil-embedded-AuthMethod",
			in:        &AuthMethod{},
			wantIsErr: db.ErrNilParameter,
		},
		{
			name: "invalid-no-scope-id",
			in: &AuthMethod{
				AuthMethod: &store.AuthMethod{},
			},
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "invalid-public-id-set",
			in: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					ScopeId:  prj.PublicId,
					PublicId: "sthc_OOOOOOOOOO",
				},
			},
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "valid-no-options",
			in: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					ScopeId: prj.PublicId,
				},
			},
			want: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					ScopeId: prj.PublicId,
				},
			},
		},
		{
			name: "valid-with-name",
			in: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					ScopeId: prj.PublicId,
					Name:    "test-name-repo",
				},
			},
			want: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					ScopeId: prj.PublicId,
					Name:    "test-name-repo",
				},
			},
		},
		{
			name: "valid-with-description",
			in: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					ScopeId:     prj.PublicId,
					Description: ("test-description-repo"),
				},
			},
			want: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					ScopeId:     prj.PublicId,
					Description: ("test-description-repo"),
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(rw, rw, wrapper)
			require.NoError(err)
			require.NotNil(repo)
			got, err := repo.CreateAuthMethod(context.Background(), tt.in, tt.opts...)
			if tt.wantIsErr != nil {
				assert.Truef(errors.Is(err, tt.wantIsErr), "want err: %q got: %q", tt.wantIsErr, err)
				assert.Nil(got)
				return
			}
			require.NoError(err)
			assert.Empty(tt.in.PublicId)
			require.NotNil(got)
			assertPublicId(t, AuthMethodPrefix, got.PublicId)
			assert.NotSame(tt.in, got)
			assert.Equal(tt.want.Name, got.Name)
			assert.Equal(tt.want.Description, got.Description)
			assert.Equal(got.CreateTime, got.UpdateTime)
		})
	}

	t.Run("invalid-duplicate-names", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(rw, rw, wrapper)
		require.NoError(err)
		require.NotNil(repo)

		_, prj := iam.TestScopes(t, conn)
		in := &AuthMethod{
			AuthMethod: &store.AuthMethod{
				ScopeId: prj.GetPublicId(),
				Name:    "test-name-repo",
			},
		}

		got, err := repo.CreateAuthMethod(context.Background(), in)
		require.NoError(err)
		require.NotNil(got)
		assertPublicId(t, AuthMethodPrefix, got.PublicId)
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)
		assert.Equal(got.CreateTime, got.UpdateTime)

		got2, err := repo.CreateAuthMethod(context.Background(), in)
		assert.Truef(errors.Is(err, db.ErrNotUnique), "want err: %v got: %v", db.ErrNotUnique, err)
		assert.Nil(got2)
	})

	t.Run("valid-duplicate-names-diff-scopes", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(rw, rw, wrapper)
		require.NoError(err)
		require.NotNil(repo)

		org, prj := iam.TestScopes(t, conn)
		in := &AuthMethod{
			AuthMethod: &store.AuthMethod{
				Name: "test-name-repo",
			},
		}
		in2 := in.clone()

		in.ScopeId = prj.GetPublicId()
		got, err := repo.CreateAuthMethod(context.Background(), in)
		require.NoError(err)
		require.NotNil(got)
		assertPublicId(t, AuthMethodPrefix, got.PublicId)
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)
		assert.Equal(got.CreateTime, got.UpdateTime)

		in2.ScopeId = org.GetPublicId()
		got2, err := repo.CreateAuthMethod(context.Background(), in2)
		require.NoError(err)
		require.NotNil(got2)
		assertPublicId(t, AuthMethodPrefix, got2.PublicId)
		assert.NotSame(in2, got2)
		assert.Equal(in2.Name, got2.Name)
		assert.Equal(in2.Description, got2.Description)
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
