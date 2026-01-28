// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package password

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/auth/password/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_GetSetConfiguration(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(context.Background(), rw, rw, kms)
	assert.NoError(t, err)
	require.NotNil(t, repo)

	o, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	authMethods := TestAuthMethods(t, conn, o.GetPublicId(), 1)
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

		require.NotEmpty(conf.PrivateId, "default configuration PrivateId")
		original = conf.PrivateId

		want := NewArgon2Configuration()
		want.PrivateId = original
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
		assert.Equal(original, currentConf.PrivateId)

		newConf := NewArgon2Configuration()
		assert.Empty(newConf.PrivateId)
		newConf.PasswordMethodId = currentConf.PasswordMethodId
		newConf.Memory = currentConf.Memory * 2

		updated, err := repo.SetConfiguration(ctx, o.GetPublicId(), newConf)
		assert.NoError(err)
		require.NotNil(updated)
		assert.NotSame(newConf, updated)

		updatedConf, ok := updated.(*Argon2Configuration)
		require.True(ok, "want *Argon2Configuration")

		assert.NotSame(newConf, updatedConf)
		assert.NotEmpty(updatedConf.PrivateId, "updatedConf.PrivateId")
		assert.NotEqual(original, updatedConf.PrivateId)

		current2, err := repo.GetConfiguration(ctx, authMethodId)
		assert.NoError(err)
		require.NotNil(current2)

		current2Conf, ok := current2.(*Argon2Configuration)
		require.True(ok, "want *Argon2Configuration")
		assert.Equal(updatedConf.PrivateId, current2Conf.PrivateId)
		assert.Equal(newConf.Memory, current2Conf.Memory, "changed setting")
	})
	t.Run("change-to-old-configuration", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		require.NotEmpty(original, "Original ID")

		newConf := NewArgon2Configuration()
		newConf.PasswordMethodId = authMethodId
		assert.Empty(newConf.PrivateId)

		updated, err := repo.SetConfiguration(ctx, o.GetPublicId(), newConf)
		assert.NoError(err)
		require.NotNil(updated)
		assert.NotSame(newConf, updated)

		updatedConf, ok := updated.(*Argon2Configuration)
		require.True(ok, "want *Argon2Configuration")

		assert.NotSame(newConf, updatedConf)
		assert.NotEmpty(updatedConf.PrivateId, "updatedConf.PrivateId")
		assert.Equal(original, updatedConf.PrivateId)

		current, err := repo.GetConfiguration(ctx, authMethodId)
		assert.NoError(err)
		require.NotNil(current)

		currentConf, ok := current.(*Argon2Configuration)
		require.True(ok, "want *Argon2Configuration")
		assert.Equal(updatedConf.PrivateId, currentConf.PrivateId)
	})
}

func TestRepository_GetConfiguration(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(context.Background(), rw, rw, kms)
	assert.NoError(t, err)
	require.NotNil(t, repo)

	o, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	authMethods := TestAuthMethods(t, conn, o.GetPublicId(), 1)
	authMethod := authMethods[0]
	authMethodId := authMethod.GetPublicId()
	ctx := context.Background()

	tests := []struct {
		name         string
		authMethodId string
		want         *Argon2Configuration
		wantIsErr    errors.Code
	}{
		{
			name:         "invalid-no-authMethodId",
			authMethodId: "",
			wantIsErr:    errors.InvalidParameter,
		},
		{
			name:         "invalid-authMethodId",
			authMethodId: "abcdefghijk",
			wantIsErr:    errors.RecordNotFound,
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
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "want err: %q got: %q", tt.wantIsErr, err)
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

func (t tconf) AuthMethodId() string           { return "abcdefghijk" }
func (t tconf) validate(context.Context) error { return nil }

var _ Configuration = tconf(0)

func TestRepository_SetConfiguration(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(context.Background(), rw, rw, kms)
	assert.NoError(t, err)
	require.NotNil(t, repo)

	o, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	authMethods := TestAuthMethods(t, conn, o.GetPublicId(), 1)
	authMethod := authMethods[0]
	authMethodId := authMethod.GetPublicId()

	tests := []struct {
		name           string
		in             Configuration
		want           *Argon2Configuration
		wantUnknownErr bool
		wantIsErr      errors.Code
	}{
		{
			name:      "invalid-nil-config",
			wantIsErr: errors.InvalidParameter,
		},
		{
			name:      "nil-embedded-config",
			in:        &Argon2Configuration{},
			wantIsErr: errors.InvalidParameter,
		},
		{
			name:      "invalid-no-authMethodId",
			in:        NewArgon2Configuration(),
			wantIsErr: errors.InvalidParameter,
		},
		{
			name:      "unknown-configuration-type",
			in:        tconf(0),
			wantIsErr: errors.PasswordUnsupportedConfiguration,
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
			name: "invalid-config-setting",
			in: &Argon2Configuration{
				Argon2Configuration: &store.Argon2Configuration{
					PasswordMethodId: authMethodId,
					Iterations:       0,
					Memory:           64 * 1024,
					Threads:          1,
					SaltLength:       32,
					KeyLength:        32,
				},
			},
			wantIsErr: errors.PasswordInvalidConfiguration,
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
			got, err := repo.SetConfiguration(context.Background(), o.GetPublicId(), tt.in)
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "want err: %q got: %q", tt.wantIsErr, err)
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

			assert.NoError(db.TestVerifyOplog(t, rw, gotConf.PrivateId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second)))
		})
	}
}
