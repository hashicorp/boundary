package static

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/credential/static/store"
	"github.com/hashicorp/boundary/internal/db"
	dbassert "github.com/hashicorp/boundary/internal/db/assert"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/libs/crypto"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_CreateUserPasswordCredential(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	cs := TestCredentialStore(t, conn, wrapper, prj.PublicId)

	tests := []struct {
		name        string
		scopeId     string
		cred        *UserPasswordCredential
		wantErr     bool
		wantErrCode errors.Code
	}{
		{
			name:        "missing-store",
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name:        "missing-embedded-cred",
			cred:        &UserPasswordCredential{},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name: "missing-scope-id",
			cred: &UserPasswordCredential{
				UserPasswordCredential: &store.UserPasswordCredential{
					Username: "my-user",
					Password: []byte("secret"),
					StoreId:  cs.PublicId,
				},
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name:    "missing-username",
			scopeId: prj.PublicId,
			cred: &UserPasswordCredential{
				UserPasswordCredential: &store.UserPasswordCredential{
					Password: []byte("secret"),
					StoreId:  cs.PublicId,
				},
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name:    "missing-password",
			scopeId: prj.PublicId,
			cred: &UserPasswordCredential{
				UserPasswordCredential: &store.UserPasswordCredential{
					Username: "my-user",
					StoreId:  cs.PublicId,
				},
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name:    "missing-store-id",
			scopeId: prj.PublicId,
			cred: &UserPasswordCredential{
				UserPasswordCredential: &store.UserPasswordCredential{
					Username: "my-user",
					Password: []byte("secret"),
				},
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name:    "valid",
			scopeId: prj.PublicId,
			cred: &UserPasswordCredential{
				UserPasswordCredential: &store.UserPasswordCredential{
					Username: "my-user",
					Password: []byte("secret"),
					StoreId:  cs.PublicId,
				},
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			ctx := context.Background()
			kkms := kms.TestKms(t, conn, wrapper)
			repo, err := NewRepository(rw, rw, kkms)
			require.NoError(err)
			require.NotNil(repo)

			got, err := repo.CreateUserPasswordCredential(ctx, tt.scopeId, tt.cred)
			if tt.wantErr {
				assert.Truef(errors.Match(errors.T(tt.wantErr), err), "want err: %q got: %q", tt.wantErr, err)
				assert.Nil(got)
				return
			}
			require.NoError(err)
			assertPublicId(t, CredentialPrefix, got.PublicId)
			assert.Equal(tt.cred.Username, got.Username)
			assert.Nil(got.Password)
			assert.Nil(got.CtPassword)

			// Validate password
			lookupCred := allocUserPasswordCredential()
			lookupCred.PublicId = got.PublicId
			require.NoError(rw.LookupById(ctx, lookupCred))

			databaseWrapper, err := kkms.GetWrapper(context.Background(), tt.scopeId, kms.KeyPurposeDatabase)
			require.NoError(err)
			require.NoError(lookupCred.decrypt(ctx, databaseWrapper))
			assert.Equal(tt.cred.Password, lookupCred.Password)

			assert.Empty(got.Password)
			assert.Empty(got.CtPassword)
			assert.NotEmpty(got.PasswordHmac)

			// Validate hmac
			hm, err := crypto.HmacSha256(ctx, tt.cred.Password, databaseWrapper, []byte(tt.cred.StoreId), nil, crypto.WithEd25519())
			require.NoError(err)
			assert.Equal([]byte(hm), got.PasswordHmac)

			// Validate oplog
			assert.NoError(db.TestVerifyOplog(t, rw, got.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second)))
		})
	}

	t.Run("duplicate-names", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()
		kms := kms.TestKms(t, conn, wrapper)
		repo, err := NewRepository(rw, rw, kms)
		require.NoError(err)
		require.NotNil(repo)
		org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		require.NoError(err)

		prjCs := TestCredentialStore(t, conn, wrapper, prj.GetPublicId())
		orgCs := TestCredentialStore(t, conn, wrapper, org.GetPublicId())

		in, err := NewUserPasswordCredential(prjCs.GetPublicId(), "user", "pass", WithName("my-name"), WithDescription("original"))
		assert.NoError(err)

		got, err := repo.CreateUserPasswordCredential(ctx, prj.PublicId, in)
		require.NoError(err)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)

		in2, err := NewUserPasswordCredential(prjCs.GetPublicId(), "user", "pass", WithName("my-name"), WithDescription("different"))
		got2, err := repo.CreateUserPasswordCredential(ctx, prj.GetPublicId(), in2)
		assert.Truef(errors.Match(errors.T(errors.NotUnique), err), "want err code: %v got err: %v", errors.NotUnique, err)
		assert.Nil(got2)

		// Creating credential in different scope should not conflict
		in3, err := NewUserPasswordCredential(orgCs.GetPublicId(), "user", "pass", WithName("my-name"), WithDescription("different"))
		got3, err := repo.CreateUserPasswordCredential(ctx, org.GetPublicId(), in3)
		require.NoError(err)
		assert.Equal(in3.Name, got3.Name)
		assert.Equal(in3.Description, got3.Description)

		assert.NotEqual(got.PublicId, got3.PublicId)
	})
}

func TestRepository_LookupCredential(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	store := TestCredentialStore(t, conn, wrapper, prj.PublicId)
	cred := TestUserPasswordCredential(t, conn, wrapper, "username", "password", store.PublicId, prj.PublicId)

	tests := []struct {
		name    string
		id      string
		want    *UserPasswordCredential
		wantErr errors.Code
	}{
		{
			name: "valid-with-client-cert",
			id:   cred.GetPublicId(),
			want: cred,
		},
		{
			name:    "empty-public-id",
			id:      "",
			wantErr: errors.InvalidParameter,
		},
		{
			name: "not-found",
			id:   "cred_fake",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			ctx := context.Background()
			kms := kms.TestKms(t, conn, wrapper)
			repo, err := NewRepository(rw, rw, kms)
			assert.NoError(err)
			require.NotNil(repo)

			got, err := repo.LookupCredential(ctx, tt.id)
			if tt.wantErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantErr), err), "want err: %q got: %q", tt.wantErr, err)
				assert.Nil(got)
				return
			}
			require.NoError(err)

			if tt.want == nil {
				assert.Nil(got)
				return
			}

			assert.NotNil(got)
			assert.Empty(got.Password)
			assert.Empty(got.CtPassword)
			assert.NotEmpty(got.PasswordHmac)
		})
	}
}

func TestRepository_ListCredentials(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	assert, require := assert.New(t), require.New(t)
	repo, err := NewRepository(rw, rw, kms)
	assert.NoError(err)
	require.NotNil(repo)

	total := 10
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	store := TestCredentialStore(t, conn, wrapper, prj.GetPublicId())
	TestUserPasswordCredentials(t, conn, wrapper, "user", "pass", store.GetPublicId(), prj.GetPublicId(), total)

	type args struct {
		storeId string
		opt     []Option
	}
	tests := []struct {
		name    string
		args    args
		wantCnt int
	}{
		{
			name: "no-limit",
			args: args{
				storeId: store.PublicId,
				opt:     []Option{WithLimit(-1)},
			},
			wantCnt: total,
		},
		{
			name: "default-limit",
			args: args{
				storeId: store.PublicId,
			},
			wantCnt: total,
		},
		{
			name: "custom-limit",
			args: args{
				storeId: store.PublicId,
				opt:     []Option{WithLimit(3)},
			},
			wantCnt: 3,
		},
		{
			name: "bad-store",
			args: args{
				storeId: "bad-id",
			},
			wantCnt: 0,
		},
	}
	for _, tt := range tests {
		got, err := repo.ListCredentials(context.Background(), tt.args.storeId, tt.args.opt...)
		require.NoError(err)
		assert.Equal(tt.wantCnt, len(got))

		// Validate only passwordHmac is returned
		for _, c := range got {
			assert.Empty(c.Password)
			assert.Empty(c.CtPassword)
			assert.NotEmpty(c.PasswordHmac)
		}
	}
}

func TestRepository_DeleteCredential(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	kms := kms.TestKms(t, conn, wrapper)
	iam.TestRepo(t, conn, wrapper)

	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	store := TestCredentialStore(t, conn, wrapper, prj.PublicId)
	cred := TestUserPasswordCredential(t, conn, wrapper, "user", "pass", store.GetPublicId(), prj.GetPublicId())

	tests := []struct {
		name        string
		in          string
		want        int
		wantErr     bool
		wantErrCode errors.Code
	}{
		{
			name:        "With no public id",
			wantErr:     true,
			wantErrCode: errors.InvalidPublicId,
		},
		{
			name: "With non existing account id",
			in:   "cred_fakeid",
			want: 0,
		},
		{
			name: "With existing id",
			in:   cred.GetPublicId(),
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
			got, err := repo.DeleteCredential(context.Background(), prj.GetPublicId(), tt.in)
			if tt.wantErr {
				assert.Truef(errors.Match(errors.T(tt.wantErrCode), err), "Unexpected error %s", err)
				return
			}
			require.NoError(err)
			assert.EqualValues(tt.want, got)
		})
	}
}

func TestRepository_UpdateUserPasswordCredential(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	changeName := func(n string) func(credential *UserPasswordCredential) *UserPasswordCredential {
		return func(c *UserPasswordCredential) *UserPasswordCredential {
			c.Name = n
			return c
		}
	}

	changeDescription := func(d string) func(*UserPasswordCredential) *UserPasswordCredential {
		return func(c *UserPasswordCredential) *UserPasswordCredential {
			c.Description = d
			return c
		}
	}

	makeNil := func() func(*UserPasswordCredential) *UserPasswordCredential {
		return func(_ *UserPasswordCredential) *UserPasswordCredential {
			return nil
		}
	}

	makeEmbeddedNil := func() func(*UserPasswordCredential) *UserPasswordCredential {
		return func(_ *UserPasswordCredential) *UserPasswordCredential {
			return &UserPasswordCredential{}
		}
	}

	deletePublicId := func() func(*UserPasswordCredential) *UserPasswordCredential {
		return func(c *UserPasswordCredential) *UserPasswordCredential {
			c.PublicId = ""
			return c
		}
	}

	deleteStoreId := func() func(*UserPasswordCredential) *UserPasswordCredential {
		return func(c *UserPasswordCredential) *UserPasswordCredential {
			c.StoreId = ""
			return c
		}
	}

	deleteVersion := func() func(*UserPasswordCredential) *UserPasswordCredential {
		return func(c *UserPasswordCredential) *UserPasswordCredential {
			c.Version = 0
			return c
		}
	}

	nonExistentPublicId := func() func(*UserPasswordCredential) *UserPasswordCredential {
		return func(c *UserPasswordCredential) *UserPasswordCredential {
			c.PublicId = "abcd_OOOOOOOOOO"
			return c
		}
	}

	changeUser := func(n string) func(credential *UserPasswordCredential) *UserPasswordCredential {
		return func(c *UserPasswordCredential) *UserPasswordCredential {
			c.Username = n
			return c
		}
	}

	changePassword := func(d string) func(*UserPasswordCredential) *UserPasswordCredential {
		return func(c *UserPasswordCredential) *UserPasswordCredential {
			c.Password = []byte(d)
			return c
		}
	}

	combine := func(fns ...func(cs *UserPasswordCredential) *UserPasswordCredential) func(*UserPasswordCredential) *UserPasswordCredential {
		return func(c *UserPasswordCredential) *UserPasswordCredential {
			for _, fn := range fns {
				c = fn(c)
			}
			return c
		}
	}

	tests := []struct {
		name      string
		orig      *UserPasswordCredential
		chgFn     func(*UserPasswordCredential) *UserPasswordCredential
		masks     []string
		want      *UserPasswordCredential
		wantCount int
		wantErr   errors.Code
	}{
		{
			name: "nil-credential",
			orig: &UserPasswordCredential{
				UserPasswordCredential: &store.UserPasswordCredential{
					Username: "user",
					Password: []byte("pass"),
				},
			},
			chgFn:   makeNil(),
			masks:   []string{"Name", "Description"},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "nil-embedded-credential",
			orig: &UserPasswordCredential{
				UserPasswordCredential: &store.UserPasswordCredential{
					Username: "user",
					Password: []byte("pass"),
				},
			},
			chgFn:   makeEmbeddedNil(),
			masks:   []string{"Name", "Description"},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "no-public-id",
			orig: &UserPasswordCredential{
				UserPasswordCredential: &store.UserPasswordCredential{
					Username: "user",
					Password: []byte("pass"),
				},
			},
			chgFn:   deletePublicId(),
			masks:   []string{"Name", "Description"},
			wantErr: errors.InvalidPublicId,
		},
		{
			name: "no-store-id",
			orig: &UserPasswordCredential{
				UserPasswordCredential: &store.UserPasswordCredential{
					Username: "user",
					Password: []byte("pass"),
				},
			},
			chgFn:   deleteStoreId(),
			masks:   []string{"Name", "Description"},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "no-version",
			orig: &UserPasswordCredential{
				UserPasswordCredential: &store.UserPasswordCredential{
					Username: "user",
					Password: []byte("pass"),
				},
			},
			chgFn:   deleteVersion(),
			masks:   []string{"Name", "Description"},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "updating-non-existent-credential",
			orig: &UserPasswordCredential{
				UserPasswordCredential: &store.UserPasswordCredential{
					Name:     "test-name-repo",
					Username: "user",
					Password: []byte("pass"),
				},
			},
			chgFn:   combine(nonExistentPublicId(), changeName("test-update-name-repo")),
			masks:   []string{"Name"},
			wantErr: errors.RecordNotFound,
		},
		{
			name: "empty-field-mask",
			orig: &UserPasswordCredential{
				UserPasswordCredential: &store.UserPasswordCredential{
					Name:     "test-name-repo",
					Username: "user",
					Password: []byte("pass"),
				},
			},
			chgFn:   changeName("test-update-name-repo"),
			wantErr: errors.EmptyFieldMask,
		},
		{
			name: "read-only-fields-in-field-mask",
			orig: &UserPasswordCredential{
				UserPasswordCredential: &store.UserPasswordCredential{
					Name:     "test-name-repo",
					Username: "user",
					Password: []byte("pass"),
				},
			},
			chgFn:   changeName("test-update-name-repo"),
			masks:   []string{"PublicId", "CreateTime", "UpdateTime", "ScopeId"},
			wantErr: errors.InvalidFieldMask,
		},
		{
			name: "unknown-field-in-field-mask",
			orig: &UserPasswordCredential{
				UserPasswordCredential: &store.UserPasswordCredential{
					Name:     "test-name-repo",
					Username: "user",
					Password: []byte("pass"),
				},
			},
			chgFn:   changeName("test-update-name-repo"),
			masks:   []string{"Bilbo"},
			wantErr: errors.InvalidFieldMask,
		},
		{
			name: "change-name",
			orig: &UserPasswordCredential{
				UserPasswordCredential: &store.UserPasswordCredential{
					Name:     "test-name-repo",
					Username: "user",
					Password: []byte("pass"),
				},
			},
			chgFn: changeName("test-update-name-repo"),
			masks: []string{"Name"},
			want: &UserPasswordCredential{
				UserPasswordCredential: &store.UserPasswordCredential{
					Name:     "test-update-name-repo",
					Username: "user",
					Password: []byte("pass"),
				},
			},
			wantCount: 1,
		},
		{
			name: "change-description",
			orig: &UserPasswordCredential{
				UserPasswordCredential: &store.UserPasswordCredential{
					Description: "test-description-repo",
					Username:    "user",
					Password:    []byte("pass"),
				},
			},
			chgFn: changeDescription("test-update-description-repo"),
			masks: []string{"Description"},
			want: &UserPasswordCredential{
				UserPasswordCredential: &store.UserPasswordCredential{
					Description: "test-update-description-repo",
					Username:    "user",
					Password:    []byte("pass"),
				},
			},
			wantCount: 1,
		},
		{
			name: "change-name-and-description",
			orig: &UserPasswordCredential{
				UserPasswordCredential: &store.UserPasswordCredential{
					Name:        "test-name-repo",
					Description: "test-description-repo",
					Username:    "user",
					Password:    []byte("pass"),
				},
			},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("test-update-name-repo")),
			masks: []string{"Name", "Description"},
			want: &UserPasswordCredential{
				UserPasswordCredential: &store.UserPasswordCredential{
					Name:        "test-update-name-repo",
					Description: "test-update-description-repo",
					Username:    "user",
					Password:    []byte("pass"),
				},
			},
			wantCount: 1,
		},
		{
			name: "change-username",
			orig: &UserPasswordCredential{
				UserPasswordCredential: &store.UserPasswordCredential{
					Username: "user",
					Password: []byte("pass"),
				},
			},
			chgFn: changeUser("test-update-user"),
			masks: []string{"Username"},
			want: &UserPasswordCredential{
				UserPasswordCredential: &store.UserPasswordCredential{
					Username: "test-update-user",
					Password: []byte("pass"),
				},
			},
			wantCount: 1,
		},
		{
			name: "change-password",
			orig: &UserPasswordCredential{
				UserPasswordCredential: &store.UserPasswordCredential{
					Username: "user",
					Password: []byte("pass"),
				},
			},
			chgFn: changePassword("test-update-pass"),
			masks: []string{"Password"},
			want: &UserPasswordCredential{
				UserPasswordCredential: &store.UserPasswordCredential{
					Username: "user",
					Password: []byte("test-update-pass"),
				},
			},
			wantCount: 1,
		},
		{
			name: "change-username-and-password",
			orig: &UserPasswordCredential{
				UserPasswordCredential: &store.UserPasswordCredential{
					Username: "user",
					Password: []byte("pass"),
				},
			},
			chgFn: combine(changeUser("test-update-user"), changePassword("test-update-pass")),
			masks: []string{"Username", "Password"},
			want: &UserPasswordCredential{
				UserPasswordCredential: &store.UserPasswordCredential{
					Username: "test-update-user",
					Password: []byte("test-update-pass"),
				},
			},
			wantCount: 1,
		},
		{
			name: "do-not-delete-password",
			orig: &UserPasswordCredential{
				UserPasswordCredential: &store.UserPasswordCredential{
					Username: "user",
					Password: []byte("pass"),
				},
			},
			masks: []string{"Username"},
			chgFn: combine(changeUser("test-new-user"), changePassword("")),
			want: &UserPasswordCredential{
				UserPasswordCredential: &store.UserPasswordCredential{
					Username: "test-new-user",
					Password: []byte("pass"),
				},
			},
			wantCount: 1,
		},
		{
			name: "do-not-delete-username",
			orig: &UserPasswordCredential{
				UserPasswordCredential: &store.UserPasswordCredential{
					Username: "user",
					Password: []byte("pass"),
				},
			},
			masks: []string{"Password"},
			chgFn: combine(changeUser(""), changePassword("test-new-password")),
			want: &UserPasswordCredential{
				UserPasswordCredential: &store.UserPasswordCredential{
					Username: "user",
					Password: []byte("test-new-password"),
				},
			},
			wantCount: 1,
		},
		{
			name: "delete-name",
			orig: &UserPasswordCredential{
				UserPasswordCredential: &store.UserPasswordCredential{
					Name:        "test-name-repo",
					Description: "test-description-repo",
					Username:    "user",
					Password:    []byte("pass"),
				},
			},
			masks: []string{"Name"},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("")),
			want: &UserPasswordCredential{
				UserPasswordCredential: &store.UserPasswordCredential{
					Description: "test-description-repo",
					Username:    "user",
					Password:    []byte("pass"),
				},
			},
			wantCount: 1,
		},
		{
			name: "delete-description",
			orig: &UserPasswordCredential{
				UserPasswordCredential: &store.UserPasswordCredential{
					Name:        "test-name-repo",
					Description: "test-description-repo",
					Username:    "user",
					Password:    []byte("pass"),
				},
			},
			masks: []string{"Description"},
			chgFn: combine(changeDescription(""), changeName("test-update-name-repo")),
			want: &UserPasswordCredential{
				UserPasswordCredential: &store.UserPasswordCredential{
					Name:     "test-name-repo",
					Username: "user",
					Password: []byte("pass"),
				},
			},
			wantCount: 1,
		},
		{
			name: "do-not-delete-name",
			orig: &UserPasswordCredential{
				UserPasswordCredential: &store.UserPasswordCredential{
					Name:        "test-name-repo",
					Description: "test-description-repo",
					Username:    "user",
					Password:    []byte("pass"),
				},
			},
			masks: []string{"Description"},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("")),
			want: &UserPasswordCredential{
				UserPasswordCredential: &store.UserPasswordCredential{
					Name:        "test-name-repo",
					Description: "test-update-description-repo",
					Username:    "user",
					Password:    []byte("pass"),
				},
			},
			wantCount: 1,
		},
		{
			name: "do-not-delete-description",
			orig: &UserPasswordCredential{
				UserPasswordCredential: &store.UserPasswordCredential{
					Name:        "test-name-repo",
					Description: "test-description-repo",
					Username:    "user",
					Password:    []byte("pass"),
				},
			},
			masks: []string{"Name"},
			chgFn: combine(changeDescription(""), changeName("test-update-name-repo")),
			want: &UserPasswordCredential{
				UserPasswordCredential: &store.UserPasswordCredential{
					Name:        "test-update-name-repo",
					Description: "test-description-repo",
					Username:    "user",
					Password:    []byte("pass"),
				},
			},
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			ctx := context.Background()
			kkms := kms.TestKms(t, conn, wrapper)
			repo, err := NewRepository(rw, rw, kkms)
			assert.NoError(err)
			require.NotNil(repo)

			_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
			store := TestCredentialStore(t, conn, wrapper, prj.GetPublicId())
			tt.orig.StoreId = store.PublicId

			orig, err := repo.CreateUserPasswordCredential(ctx, prj.GetPublicId(), tt.orig)
			assert.NoError(err)
			require.NotNil(orig)

			if tt.chgFn != nil {
				orig = tt.chgFn(orig)
			}
			var version uint32
			if orig != nil {
				version = orig.GetVersion()
			}
			got, gotCount, err := repo.UpdateUserPasswordCredential(ctx, prj.GetPublicId(), orig, version, tt.masks)
			if tt.wantErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantErr), err), "want err: %q got: %q", tt.wantErr, err)
				assert.Equal(tt.wantCount, gotCount, "row count")
				assert.Nil(got)
				return
			}
			assert.NoError(err)
			assert.Empty(tt.orig.PublicId)
			require.NotNil(got)
			assertPublicId(t, CredentialPrefix, got.PublicId)
			assert.Equal(tt.wantCount, gotCount, "row count")
			assert.NotSame(tt.orig, got)
			assert.Equal(tt.orig.StoreId, got.StoreId)
			underlyingDB, err := conn.SqlDB(ctx)
			require.NoError(err)
			dbassert := dbassert.New(t, underlyingDB)
			if tt.want.Name == "" {
				got := got.clone()
				dbassert.IsNull(got, "name")
			} else {
				assert.Equal(tt.want.Name, got.Name)
			}

			if tt.want.Description == "" {
				got := got.clone()
				dbassert.IsNull(got, "description")
			} else {
				assert.Equal(tt.want.Description, got.Description)
			}

			assert.Equal(tt.want.Username, got.Username)

			// Validate only passwordHmac is returned
			assert.Empty(got.Password)
			assert.Empty(got.CtPassword)
			assert.NotEmpty(got.PasswordHmac)

			// Validate hmac
			databaseWrapper, err := kkms.GetWrapper(context.Background(), prj.GetPublicId(), kms.KeyPurposeDatabase)
			require.NoError(err)
			hm, err := crypto.HmacSha256(ctx, tt.want.Password, databaseWrapper, []byte(store.GetPublicId()), nil, crypto.WithEd25519())
			require.NoError(err)
			assert.Equal([]byte(hm), got.PasswordHmac)

			if tt.wantCount > 0 {
				assert.NoError(db.TestVerifyOplog(t, rw, got.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))
			}
		})
	}
}
