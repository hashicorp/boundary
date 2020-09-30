package password

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/auth/password/store"
	"github.com/hashicorp/boundary/internal/db"
	dbassert "github.com/hashicorp/boundary/internal/db/assert"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestRepository_CreateAuthMethod(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iamRepo)

	var tests = []struct {
		name      string
		in        *AuthMethod
		opts      []Option
		want      *AuthMethod
		wantIsErr error
	}{
		{
			name:      "nil-AuthMethod",
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name:      "nil-embedded-AuthMethod",
			in:        &AuthMethod{},
			wantIsErr: db.ErrInvalidParameter,
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
					ScopeId:  org.PublicId,
					PublicId: "hcst_OOOOOOOOOO",
				},
			},
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "valid-no-options",
			in: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					ScopeId: org.PublicId,
				},
			},
			want: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					ScopeId: org.PublicId,
				},
			},
		},
		{
			name: "valid-with-name",
			in: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					ScopeId: org.PublicId,
					Name:    "test-name-repo",
				},
			},
			want: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					ScopeId: org.PublicId,
					Name:    "test-name-repo",
				},
			},
		},
		{
			name: "valid-with-description",
			in: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					ScopeId:     org.PublicId,
					Description: ("test-description-repo"),
				},
			},
			want: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					ScopeId:     org.PublicId,
					Description: ("test-description-repo"),
				},
			},
		},
		{
			name: "invalid-with-config-nil-embedded-config",
			in: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					ScopeId: org.PublicId,
				},
			},
			opts: []Option{
				WithConfiguration(&Argon2Configuration{}),
			},
			wantIsErr: ErrInvalidConfiguration,
		},
		{
			name: "invalid-with-config-unknown-config-type",
			in: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					ScopeId: org.PublicId,
				},
			},
			opts: []Option{
				WithConfiguration(tconf(0)),
			},
			wantIsErr: ErrUnsupportedConfiguration,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(rw, rw, kms)
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
		repo, err := NewRepository(rw, rw, kms)
		require.NoError(err)
		require.NotNil(repo)

		org, _ := iam.TestScopes(t, iamRepo)
		in := &AuthMethod{
			AuthMethod: &store.AuthMethod{
				ScopeId: org.GetPublicId(),
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
		repo, err := NewRepository(rw, rw, kms)
		require.NoError(err)
		require.NotNil(repo)

		org1, _ := iam.TestScopes(t, iamRepo)
		in := &AuthMethod{
			AuthMethod: &store.AuthMethod{
				Name: "test-name-repo",
			},
		}
		in2 := in.clone()

		in.ScopeId = org1.GetPublicId()
		got, err := repo.CreateAuthMethod(context.Background(), in)
		require.NoError(err)
		require.NotNil(got)
		assertPublicId(t, AuthMethodPrefix, got.PublicId)
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)
		assert.Equal(got.CreateTime, got.UpdateTime)

		org2, _ := iam.TestScopes(t, iamRepo)
		in2.ScopeId = org2.GetPublicId()
		got2, err := repo.CreateAuthMethod(context.Background(), in2)
		require.NoError(err)
		require.NotNil(got2)
		assertPublicId(t, AuthMethodPrefix, got2.PublicId)
		assert.NotSame(in2, got2)
		assert.Equal(in2.Name, got2.Name)
		assert.Equal(in2.Description, got2.Description)
		assert.Equal(got2.CreateTime, got2.UpdateTime)
	})

	t.Run("valid-with-publicid", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(rw, rw, kms)
		require.NoError(err)
		require.NotNil(repo)

		org1, _ := iam.TestScopes(t, iamRepo)
		in := allocAuthMethod()

		amId, err := newAuthMethodId()
		require.NoError(err)

		in.ScopeId = org1.GetPublicId()
		got, err := repo.CreateAuthMethod(context.Background(), &in, WithPublicId(amId))
		require.NoError(err)
		require.NotNil(got)
		assert.Equal(amId, got.GetPublicId())
		assert.Equal(got.CreateTime, got.UpdateTime)
	})

	t.Run("invalid-with-badpublicid", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(rw, rw, kms)
		require.NoError(err)
		require.NotNil(repo)

		org1, _ := iam.TestScopes(t, iamRepo)
		in := allocAuthMethod()

		in.ScopeId = org1.GetPublicId()
		got, err := repo.CreateAuthMethod(context.Background(), &in, WithPublicId("invalid_idwithabadprefix"))
		assert.Error(err)
		assert.Nil(got)
		assert.True(errors.Is(err, db.ErrInvalidPublicId))
	})
}

func TestRepository_LookupAuthMethod(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	o, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	authMethod := TestAuthMethods(t, conn, o.GetPublicId(), 1)[0]

	amId, err := newAuthMethodId()
	require.NoError(t, err)
	var tests = []struct {
		name      string
		in        string
		want      *AuthMethod
		wantIsErr error
	}{
		{
			name:      "With no public id",
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "With non existing auth method id",
			in:   amId,
		},
		{
			name: "With existing auth method id",
			in:   authMethod.GetPublicId(),
			want: authMethod,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(rw, rw, kms)
			assert.NoError(err)
			require.NotNil(repo)
			got, err := repo.LookupAuthMethod(context.Background(), tt.in)
			if tt.wantIsErr != nil {
				assert.Truef(errors.Is(err, tt.wantIsErr), "want err: %q got: %q", tt.wantIsErr, err)
				assert.Nil(got)
				return
			}
			require.NoError(err)
			assert.EqualValues(tt.want, got)
		})
	}
}

func TestRepository_DeleteAuthMethod(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	o, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	authMethod := TestAuthMethods(t, conn, o.GetPublicId(), 1)[0]

	newAuthMethodId, err := newAuthMethodId()
	require.NoError(t, err)
	var tests = []struct {
		name      string
		in        string
		want      int
		wantIsErr error
	}{
		{
			name:      "With no public id",
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "With non existing auth method id",
			in:   newAuthMethodId,
			want: 0,
		},
		{
			name: "With existing auth method id",
			in:   authMethod.GetPublicId(),
			want: 1,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(rw, rw, kms)
			assert.NoError(err)
			require.NotNil(repo)
			got, err := repo.DeleteAuthMethod(context.Background(), o.GetPublicId(), tt.in)
			if tt.wantIsErr != nil {
				assert.Truef(errors.Is(err, tt.wantIsErr), "want err: %q got: %q", tt.wantIsErr, err)
				assert.Zero(got)
				return
			}
			require.NoError(err)
			assert.EqualValues(tt.want, got)
		})
	}
}

func TestRepository_ListAuthMethods(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	noAuthMethodOrg, _ := iam.TestScopes(t, iamRepo)
	o, _ := iam.TestScopes(t, iamRepo)
	authMethods := TestAuthMethods(t, conn, o.GetPublicId(), 3)

	var tests = []struct {
		name      string
		in        string
		opts      []Option
		want      []*AuthMethod
		wantIsErr error
	}{
		{
			name:      "With no scope id",
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "Scope with no auth methods",
			in:   noAuthMethodOrg.GetPublicId(),
			want: []*AuthMethod{},
		},
		{
			name: "With populated scope id",
			in:   o.GetPublicId(),
			want: authMethods,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(rw, rw, kms)
			assert.NoError(err)
			require.NotNil(repo)
			got, err := repo.ListAuthMethods(context.Background(), tt.in, tt.opts...)
			if tt.wantIsErr != nil {
				assert.Truef(errors.Is(err, tt.wantIsErr), "want err: %q got: %q", tt.wantIsErr, err)
				assert.Nil(got)
				return
			}
			require.NoError(err)
			assert.Empty(cmp.Diff(tt.want, got, protocmp.Transform()))
		})
	}
}

func TestRepository_ListAuthMethods_Limits(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	o, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	authMethodCount := 10
	ams := TestAuthMethods(t, conn, o.GetPublicId(), authMethodCount)

	var tests = []struct {
		name     string
		repoOpts []Option
		listOpts []Option
		wantLen  int
	}{
		{
			name:    "With no limits",
			wantLen: authMethodCount,
		},
		{
			name:     "With repo limit",
			repoOpts: []Option{WithLimit(3)},
			wantLen:  3,
		},
		{
			name:     "With negative repo limit",
			repoOpts: []Option{WithLimit(-1)},
			wantLen:  authMethodCount,
		},
		{
			name:     "With List limit",
			listOpts: []Option{WithLimit(3)},
			wantLen:  3,
		},
		{
			name:     "With negative List limit",
			listOpts: []Option{WithLimit(-1)},
			wantLen:  authMethodCount,
		},
		{
			name:     "With repo smaller than list limit",
			repoOpts: []Option{WithLimit(2)},
			listOpts: []Option{WithLimit(6)},
			wantLen:  6,
		},
		{
			name:     "With repo larger than list limit",
			repoOpts: []Option{WithLimit(6)},
			listOpts: []Option{WithLimit(2)},
			wantLen:  2,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(rw, rw, kms, tt.repoOpts...)
			assert.NoError(err)
			require.NotNil(repo)
			got, err := repo.ListAuthMethods(context.Background(), ams[0].GetScopeId(), tt.listOpts...)
			require.NoError(err)
			assert.Len(got, tt.wantLen)
		})
	}
}

func TestRepository_UpdateAuthMethod(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(rw, rw, kms)
	require.NoError(t, err)
	iamRepo := iam.TestRepo(t, conn, wrapper)

	ctx := context.Background()

	type args struct {
		updates        *store.AuthMethod
		fieldMaskPaths []string
	}
	tests := []struct {
		name             string
		args             args
		wantRowsUpdate   int
		wantErr          bool
		skipVersionCheck bool
	}{
		{
			name: "change name",
			args: args{
				updates: &store.AuthMethod{
					Name: "updated",
				},
				fieldMaskPaths: []string{"Name"},
			},
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "null name",
			args: args{
				updates:        &store.AuthMethod{},
				fieldMaskPaths: []string{"Name"},
			},
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "change description",
			args: args{
				updates: &store.AuthMethod{
					Description: "updated",
				},
				fieldMaskPaths: []string{"Description"},
			},
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "null description",
			args: args{
				updates:        &store.AuthMethod{},
				fieldMaskPaths: []string{"Description"},
			},
			wantErr:          false,
			wantRowsUpdate:   1,
			skipVersionCheck: true,
		},
		{
			name: "null name ignored description",
			args: args{
				updates:        &store.AuthMethod{Description: "ignored"},
				fieldMaskPaths: []string{"name"},
			},
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "change min pw",
			args: args{
				updates: &store.AuthMethod{
					MinPasswordLength: 13,
				},
				fieldMaskPaths: []string{"MinPasswordLength"},
			},
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "null min pw",
			args: args{
				updates:        &store.AuthMethod{},
				fieldMaskPaths: []string{"MinPasswordLength"},
			},
			wantErr:          false,
			wantRowsUpdate:   1,
			skipVersionCheck: true,
		},
		{
			name: "change min login name",
			args: args{
				updates: &store.AuthMethod{
					MinLoginNameLength: 13,
				},
				fieldMaskPaths: []string{"MinLoginNameLength"},
			},
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "null min login name",
			args: args{
				updates:        &store.AuthMethod{},
				fieldMaskPaths: []string{"MinLoginNameLength"},
			},
			wantErr:          false,
			wantRowsUpdate:   1,
			skipVersionCheck: true,
		},
		{
			name: "noop update",
			args: args{
				updates: &store.AuthMethod{
					Name: "default",
				},
				fieldMaskPaths: []string{"name"},
			},
			wantErr:          false,
			wantRowsUpdate:   1,
			skipVersionCheck: true,
		},
		{
			name: "not fround",
			args: args{
				updates: &store.AuthMethod{
					PublicId: func() string {
						s, err := newAuthMethodId()
						require.NoError(t, err)
						return s
					}(),
				},
				fieldMaskPaths: []string{"name"},
			},
			wantErr:        true,
			wantRowsUpdate: 0,
		},
		{
			name: "empty field mask",
			args: args{
				updates:        &store.AuthMethod{Name: "Test"},
				fieldMaskPaths: []string{},
			},
			wantErr:        true,
			wantRowsUpdate: 0,
		},
		{
			name: "nil field mask",
			args: args{
				updates:        &store.AuthMethod{Name: "Test"},
				fieldMaskPaths: nil,
			},
			wantErr:        true,
			wantRowsUpdate: 0,
		},
		{
			name: "read-only-fields",
			args: args{
				updates:        &store.AuthMethod{Name: "Test"},
				fieldMaskPaths: []string{"CreateTime"},
			},
			wantErr:        true,
			wantRowsUpdate: 0,
		},
		{
			name: "unknown fields",
			args: args{
				updates:        &store.AuthMethod{Name: "Test"},
				fieldMaskPaths: []string{"RandomUnknownName"},
			},
			wantErr:        true,
			wantRowsUpdate: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			// create the initial auth method
			o, _ := iam.TestScopes(t, iamRepo)
			am, err := NewAuthMethod(o.GetPublicId(), WithName("default"), WithDescription("default"))
			require.NoError(err)
			origAM, err := repo.CreateAuthMethod(ctx, am)
			require.NoError(err)
			assert.EqualValues(1, origAM.Version)

			amToUpdate, err := NewAuthMethod(o.GetPublicId())
			require.NoError(err)
			amToUpdate.PublicId = origAM.GetPublicId()
			amToUpdate.Version = origAM.Version
			proto.Merge(amToUpdate.AuthMethod, tt.args.updates)
			assert.EqualValues(1, amToUpdate.Version)

			updatedAM, updatedRows, err := repo.UpdateAuthMethod(ctx, amToUpdate, amToUpdate.Version, tt.args.fieldMaskPaths)
			assert.Equal(tt.wantRowsUpdate, updatedRows)
			if tt.wantErr {
				require.Error(err)
				assert.Nil(updatedAM)
				err = db.TestVerifyOplog(t, rw, amToUpdate.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
				require.Error(err)
				assert.Equal("record not found", err.Error())
				return
			}
			require.NoError(err)
			if !tt.skipVersionCheck {
				assert.EqualValues(2, updatedAM.Version)
			}
			assert.NotEqual(origAM.UpdateTime, updatedAM.UpdateTime)
			foundAuthMethod, err := repo.LookupAuthMethod(ctx, origAM.PublicId)
			require.NoError(err)
			assert.Empty(cmp.Diff(updatedAM, foundAuthMethod, protocmp.Transform()))

			dbassert := dbassert.New(t, conn.DB())
			if amToUpdate.Name == "" && contains(tt.args.fieldMaskPaths, "name") {
				dbassert.IsNull(foundAuthMethod, "name")
			}
			if amToUpdate.Description == "" && contains(tt.args.fieldMaskPaths, "description") {
				dbassert.IsNull(foundAuthMethod, "description")
			}

			err = db.TestVerifyOplog(t, rw, updatedAM.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)
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
