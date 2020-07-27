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

func TestRepository_GetSetConfiguration(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo, err := NewRepository(rw, rw, wrapper)
	assert.NoError(t, err)
	require.NotNil(t, repo)

	authMethods := testAuthMethods(t, conn, 1)
	authMethod := authMethods[0]
	authMethodId := authMethod.GetPublicId()
	ctx := context.Background()

	// The order of these tests are important. Some tests have a dependency
	// on prior tests.

	var original string // original configuration ID

	t.Run("has-default-configuration", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		got, err := repo.GetConfiguration(ctx, authMethodId)
		assert.NoError(err)
		require.NotNil(got)

		conf, ok := got.(*Argon2Configuration)
		require.True(ok, "want *Argon2Configuration")

		require.NotEmpty(conf.PublicId, "default configuration PublicId")
		original = conf.PublicId

		want := NewArgon2Configuration()
		want.PublicId = original
		want.CreateTime = conf.CreateTime
		want.PasswordMethodId = authMethodId
		require.Equal(want, got)
	})
	t.Run("change-configuration", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		require.NotEmpty(original, "Original ID")

		current, err := repo.GetConfiguration(ctx, authMethodId)
		assert.NoError(err)
		require.NotNil(current)

		currentConf, ok := current.(*Argon2Configuration)
		require.True(ok, "want *Argon2Configuration")
		assert.Equal(original, currentConf.PublicId)

		newConf := NewArgon2Configuration()
		assert.Empty(newConf.PublicId)
		newConf.PasswordMethodId = currentConf.PasswordMethodId
		newConf.Memory = currentConf.Memory * 2

		updated, err := repo.SetConfiguration(ctx, newConf)
		assert.NoError(err)
		require.NotNil(updated)
		assert.NotSame(newConf, updated)

		updatedConf, ok := updated.(*Argon2Configuration)
		require.True(ok, "want *Argon2Configuration")

		assert.NotSame(newConf, updatedConf)
		assert.NotEmpty(updatedConf.PublicId, "updatedConf.PublicId")
		assert.NotEqual(original, updatedConf.PublicId)

		current2, err := repo.GetConfiguration(ctx, authMethodId)
		assert.NoError(err)
		require.NotNil(current2)

		current2Conf, ok := current2.(*Argon2Configuration)
		require.True(ok, "want *Argon2Configuration")
		assert.Equal(updatedConf.PublicId, current2Conf.PublicId)
		assert.Equal(newConf.Memory, current2Conf.Memory, "changed setting")
	})
	t.Run("change-to-old-configuration", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		require.NotEmpty(original, "Original ID")

		newConf := NewArgon2Configuration()
		newConf.PasswordMethodId = authMethodId
		assert.Empty(newConf.PublicId)

		updated, err := repo.SetConfiguration(ctx, newConf)
		assert.NoError(err)
		require.NotNil(updated)
		assert.NotSame(newConf, updated)

		updatedConf, ok := updated.(*Argon2Configuration)
		require.True(ok, "want *Argon2Configuration")

		assert.NotSame(newConf, updatedConf)
		assert.NotEmpty(updatedConf.PublicId, "updatedConf.PublicId")
		assert.Equal(original, updatedConf.PublicId)

		current, err := repo.GetConfiguration(ctx, authMethodId)
		assert.NoError(err)
		require.NotNil(current)

		currentConf, ok := current.(*Argon2Configuration)
		require.True(ok, "want *Argon2Configuration")
		assert.Equal(updatedConf.PublicId, currentConf.PublicId)
	})
}

func TestRepository_GetConfiguration(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo, err := NewRepository(rw, rw, wrapper)
	assert.NoError(t, err)
	require.NotNil(t, repo)

	authMethods := testAuthMethods(t, conn, 1)
	authMethod := authMethods[0]
	authMethodId := authMethod.GetPublicId()
	ctx := context.Background()

	var tests = []struct {
		name         string
		authMethodId string
		want         *Argon2Configuration
		wantIsErr    error
	}{
		{
			name:         "invalid-no-authMethodId",
			authMethodId: "",
			wantIsErr:    db.ErrInvalidParameter,
		},
		{
			name:         "invalid-authMethodId",
			authMethodId: "abcdefghijk",
			wantIsErr:    db.ErrRecordNotFound,
		},
		{
			name:         "valid-authMethodId",
			authMethodId: authMethodId,
			want:         NewArgon2Configuration(),
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := repo.GetConfiguration(ctx, tt.authMethodId)
			if tt.wantIsErr != nil {
				assert.Truef(errors.Is(err, tt.wantIsErr), "want err: %q got: %q", tt.wantIsErr, err)
				assert.Nil(got, "returned configuration")
				return
			}
			require.NoError(err)
			gotConf, ok := got.(*Argon2Configuration)
			require.True(ok, "want *Argon2Configuration")

			tt.want.PasswordMethodId = tt.authMethodId

			assert.Equal(tt.authMethodId, gotConf.AuthMethodId(), "authMethodId")

			assert.Equal(tt.want.PasswordMethodId, gotConf.PasswordMethodId)
			assert.Equal(tt.want.Iterations, gotConf.Iterations)
			assert.Equal(tt.want.Memory, gotConf.Memory)
			assert.Equal(tt.want.Threads, gotConf.Threads)
			assert.Equal(tt.want.SaltLength, gotConf.SaltLength)
			assert.Equal(tt.want.KeyLength, gotConf.KeyLength)
		})
	}
}

type tconf int
func (t tconf) AuthMethodId() string { return "abcdefghijk" }
var _ Configuration = tconf(0)

func TestRepository_SetConfiguration(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo, err := NewRepository(rw, rw, wrapper)
	assert.NoError(t, err)
	require.NotNil(t, repo)

	authMethods := testAuthMethods(t, conn, 1)
	authMethod := authMethods[0]
	authMethodId := authMethod.GetPublicId()

	var tests = []struct {
		name           string
		in             Configuration
		want           *Argon2Configuration
		wantUnknownErr bool
		wantIsErr      error
	}{
		{
			name:      "invalid-nil-config",
			wantIsErr: db.ErrNilParameter,
		},
		{
			name:      "invalid-no-authMethodId",
			in:        NewArgon2Configuration(),
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name:      "unknown-configuration-type",
			in:        tconf(0),
			wantIsErr: ErrUnsupportedConfiguration,
		},
		{
			name: "invalid-unknown-authMethodId",
			in: &Argon2Configuration{
				Argon2Configuration: &store.Argon2Configuration{
					PasswordMethodId: "abcdefghijk",
					Iterations:       3 * 2,
					Memory:           64 * 1024,
					Threads:          1,
					SaltLength:       32,
					KeyLength:        32,
				},
			},
			wantUnknownErr: true,
		},
		{
			name: "valid",
			in: &Argon2Configuration{
				Argon2Configuration: &store.Argon2Configuration{
					PasswordMethodId: authMethodId,
					Iterations:       3 * 2,
					Memory:           64 * 1024,
					Threads:          1,
					SaltLength:       32,
					KeyLength:        32,
				},
			},
			want: &Argon2Configuration{
				Argon2Configuration: &store.Argon2Configuration{
					PasswordMethodId: authMethodId,
					Iterations:       3 * 2,
					Memory:           64 * 1024,
					Threads:          1,
					SaltLength:       32,
					KeyLength:        32,
				},
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := repo.SetConfiguration(context.Background(), tt.in)
			if tt.wantIsErr != nil {
				assert.Truef(errors.Is(err, tt.wantIsErr), "want err: %q got: %q", tt.wantIsErr, err)
				assert.Nil(got, "returned configuration")
				return
			}
			if tt.wantUnknownErr {
				assert.Error(err)
				return
			}
			require.NoError(err)

			assert.NotSame(tt.in, got)

			gotConf, ok := got.(*Argon2Configuration)
			require.True(ok, "want *Argon2Configuration")

			assert.Equal(tt.want.PasswordMethodId, gotConf.PasswordMethodId)
			assert.Equal(tt.want.Iterations, gotConf.Iterations)
			assert.Equal(tt.want.Memory, gotConf.Memory)
			assert.Equal(tt.want.Threads, gotConf.Threads)
			assert.Equal(tt.want.SaltLength, gotConf.SaltLength)
			assert.Equal(tt.want.KeyLength, gotConf.KeyLength)
		})
	}
}
