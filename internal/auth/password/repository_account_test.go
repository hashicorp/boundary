package password

import (
	"context"
	"errors"
	"testing"

	"github.com/hashicorp/watchtower/internal/auth/password/store"
	"github.com/hashicorp/watchtower/internal/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckUserName(t *testing.T) {
	var tests = []struct {
		in   string
		want bool
	}{
		{"", false},
		{" leading-spaces", false},
		{"trailing-spaces ", false},
		{"contains spaces", false},
		{"NotLowerCase", false},
		{"valid.username", true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.in, func(t *testing.T) {
			assert.Equal(t, tt.want, validUserName(tt.in))
		})
	}
}

func TestRepository_CreateAccount(t *testing.T) {
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	t.Cleanup(func() {
		err := cleanup()
		assert.NoError(t, err)
		err = conn.Close()
		assert.NoError(t, err)
	})
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	authMethods := testAuthMethods(t, conn, 1)
	authMethod := authMethods[0]

	// TODO(mgaffney) 06/2020: add tests for:
	// - username to small for default min length
	// - username to small for custom min length

	var tests = []struct {
		name      string
		in        *Account
		opts      []Option
		want      *Account
		wantIsErr error
	}{
		{
			name:      "nil-Account",
			wantIsErr: db.ErrNilParameter,
		},
		{
			name:      "nil-embedded-Account",
			in:        &Account{},
			wantIsErr: db.ErrNilParameter,
		},
		{
			name: "invalid-no-scope-id",
			in: &Account{
				Account: &store.Account{},
			},
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "invalid-public-id-set",
			in: &Account{
				Account: &store.Account{
					AuthMethodId: authMethod.PublicId,
					PublicId:     "sthc_OOOOOOOOOO",
				},
			},
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "invalid-username-uppercase",
			in: &Account{
				Account: &store.Account{
					AuthMethodId: authMethod.PublicId,
					UserName:     "KaZmiErcZak11",
				},
			},
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "invalid-username-leading-space",
			in: &Account{
				Account: &store.Account{
					AuthMethodId: authMethod.PublicId,
					UserName:     " kazmierczak12",
				},
			},
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "invalid-username-trailing-space",
			in: &Account{
				Account: &store.Account{
					AuthMethodId: authMethod.PublicId,
					UserName:     "kazmierczak13 ",
				},
			},
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "invalid-username-space-in-name",
			in: &Account{
				Account: &store.Account{
					AuthMethodId: authMethod.PublicId,
					UserName:     "kazmier czak14",
				},
			},
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "invalid-username-to-short",
			in: &Account{
				Account: &store.Account{
					AuthMethodId: authMethod.PublicId,
					UserName:     "kaz",
				},
			},
			wantIsErr: ErrTooShort,
		},
		{
			name: "valid-no-options",
			in: &Account{
				Account: &store.Account{
					AuthMethodId: authMethod.PublicId,
					UserName:     "kazmierczak",
				},
			},
			want: &Account{
				Account: &store.Account{
					AuthMethodId: authMethod.PublicId,
					UserName:     "kazmierczak",
				},
			},
		},
		{
			name: "valid-with-name",
			in: &Account{
				Account: &store.Account{
					AuthMethodId: authMethod.PublicId,
					Name:         "test-name-repo",
					UserName:     "kazmierczak1",
				},
			},
			want: &Account{
				Account: &store.Account{
					AuthMethodId: authMethod.PublicId,
					Name:         "test-name-repo",
					UserName:     "kazmierczak1",
				},
			},
		},
		{
			name: "valid-with-description",
			in: &Account{
				Account: &store.Account{
					AuthMethodId: authMethod.PublicId,
					Description:  ("test-description-repo"),
					UserName:     "kazmierczak2",
				},
			},
			want: &Account{
				Account: &store.Account{
					AuthMethodId: authMethod.PublicId,
					Description:  ("test-description-repo"),
					UserName:     "kazmierczak2",
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(rw, rw, wrapper)
			assert.NoError(err)
			require.NotNil(repo)
			got, err := repo.CreateAccount(context.Background(), tt.in, tt.opts...)
			if tt.wantIsErr != nil {
				assert.Truef(errors.Is(err, tt.wantIsErr), "want err: %q got: %q", tt.wantIsErr, err)
				assert.Nil(got)
				return
			}
			require.NoError(err)
			assert.Empty(tt.in.PublicId)
			require.NotNil(got)
			assertPublicId(t, AccountPrefix, got.PublicId)
			assert.NotSame(tt.in, got)
			assert.Equal(tt.want.Name, got.Name)
			assert.Equal(tt.want.Description, got.Description)
			assert.Equal(got.CreateTime, got.UpdateTime)
		})
	}

	t.Run("invalid-duplicate-names", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(rw, rw, wrapper)
		assert.NoError(err)
		require.NotNil(repo)

		authMethods := testAuthMethods(t, conn, 1)
		authMethod := authMethods[0]

		in := &Account{
			Account: &store.Account{
				AuthMethodId: authMethod.GetPublicId(),
				Name:         "test-name-repo",
				UserName:     "kazmierczak3",
			},
		}

		got, err := repo.CreateAccount(context.Background(), in)
		require.NoError(err)
		require.NotNil(got)
		assertPublicId(t, AccountPrefix, got.PublicId)
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)
		assert.Equal(got.CreateTime, got.UpdateTime)

		got2, err := repo.CreateAccount(context.Background(), in)
		assert.Truef(errors.Is(err, db.ErrNotUnique), "want err: %v got: %v", db.ErrNotUnique, err)
		assert.Nil(got2)
	})

	t.Run("valid-duplicate-names-diff-parents", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(rw, rw, wrapper)
		assert.NoError(err)
		require.NotNil(repo)

		authMethods := testAuthMethods(t, conn, 2)
		authMethoda, authMethodb := authMethods[0], authMethods[1]
		in := &Account{
			Account: &store.Account{
				Name:     "test-name-repo",
				UserName: "kazmierczak4",
			},
		}
		in2 := in.clone()

		in.AuthMethodId = authMethoda.GetPublicId()
		got, err := repo.CreateAccount(context.Background(), in)
		require.NoError(err)
		require.NotNil(got)
		assertPublicId(t, AccountPrefix, got.PublicId)
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)
		assert.Equal(got.CreateTime, got.UpdateTime)

		in2.AuthMethodId = authMethodb.GetPublicId()
		got2, err := repo.CreateAccount(context.Background(), in2)
		assert.NoError(err)
		require.NotNil(got2)
		assertPublicId(t, AccountPrefix, got2.PublicId)
		assert.NotSame(in2, got2)
		assert.Equal(in2.Name, got2.Name)
		assert.Equal(in2.Description, got2.Description)
		assert.Equal(got2.CreateTime, got2.UpdateTime)
	})
}
