package password

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/watchtower/internal/auth/password/store"
	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/oplog"
	"github.com/jinzhu/gorm"
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

func testAccounts(t *testing.T, conn *gorm.DB, scopeId, authMethodId string, count int) []*Account {
	t.Helper()
	assert, require := assert.New(t), require.New(t)
	w := db.New(conn)
	var auts []*Account
	for i := 0; i < count; i++ {
		cat, err := NewAccount(authMethodId, fmt.Sprintf("name%d", i))
		assert.NoError(err)
		require.NotNil(cat)
		id, err := newAuthMethodId()
		assert.NoError(err)
		require.NotEmpty(id)
		cat.PublicId = id

		ctx := context.Background()
		_, err2 := w.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
			func(_ db.Reader, iw db.Writer) error {
				return iw.Create(ctx, cat)
			},
		)

		require.NoError(err2)
		// TODO(toddknight): Figure out why the iw.Create call doesn't populate the scope id from the DB.
		cat.ScopeId = scopeId
		auts = append(auts, cat)
	}
	return auts
}

func TestRepository_CreateAccount(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	authMethods := testAuthMethods(t, conn, 1)
	authMethod := authMethods[0]

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
			name: "invalid-password-to-short",
			in: &Account{
				Account: &store.Account{
					AuthMethodId: authMethod.PublicId,
					UserName:     "kazmierczak123",
				},
			},
			opts: []Option{
				WithPassword("a"),
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
		{
			name: "valid-with-password",
			in: &Account{
				Account: &store.Account{
					AuthMethodId: authMethod.PublicId,
					UserName:     "kazmierczak3",
				},
			},
			opts: []Option{
				WithPassword("1234567890"),
			},
			want: &Account{
				Account: &store.Account{
					AuthMethodId: authMethod.PublicId,
					UserName:     "kazmierczak3",
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

			assert.NoError(db.TestVerifyOplog(t, rw, got.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second)))

			opts := getOpts(tt.opts...)
			if opts.withPassword {
				authAcct, err := repo.Authenticate(context.Background(), tt.in.AuthMethodId, tt.in.UserName, opts.password)
				require.NoError(err)
				assert.NoError(db.TestVerifyOplog(t, rw, authAcct.CredentialID, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second)))
			}
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

func TestRepository_LookupAccount(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	authMethod := testAuthMethods(t, conn, 1)[0]
	account := testAccounts(t, conn, authMethod.GetScopeId(), authMethod.GetPublicId(), 1)[0]

	newAcctId, err := newAccountId()
	require.NoError(t, err)
	var tests = []struct {
		name      string
		in        string
		want      *Account
		wantIsErr error
	}{
		{
			name:      "With no public id",
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "With non existing account id",
			in:   newAcctId,
		},
		{
			name: "With existing account id",
			in:   account.GetPublicId(),
			want: account,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(rw, rw, wrapper)
			assert.NoError(err)
			require.NotNil(repo)
			got, err := repo.LookupAccount(context.Background(), tt.in)
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

func TestRepository_DeleteAccount(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	authMethod := testAuthMethods(t, conn, 1)[0]
	account := testAccounts(t, conn, authMethod.GetScopeId(), authMethod.GetPublicId(), 1)[0]

	newAcctId, err := newAccountId()
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
			name: "With non existing account id",
			in:   newAcctId,
			want: 0,
		},
		{
			name: "With existing account id",
			in:   account.GetPublicId(),
			want: 1,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(rw, rw, wrapper)
			assert.NoError(err)
			require.NotNil(repo)
			got, err := repo.DeleteAccount(context.Background(), tt.in)
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

func TestRepository_ListAccounts(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	authMethods := testAuthMethods(t, conn, 3)
	accounts1 := testAccounts(t, conn, authMethods[0].GetScopeId(), authMethods[0].GetPublicId(), 3)
	accounts2 := testAccounts(t, conn, authMethods[1].GetScopeId(), authMethods[1].GetPublicId(), 4)
	_ = accounts2

	var tests = []struct {
		name      string
		in        string
		opts      []Option
		want      []*Account
		wantIsErr error
	}{
		{
			name:      "With no auth method id",
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "With no accounts id",
			in:   authMethods[2].GetPublicId(),
			want: []*Account{},
		},
		{
			name: "With first auth method id",
			in:   authMethods[0].GetPublicId(),
			want: accounts1,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(rw, rw, wrapper)
			assert.NoError(err)
			require.NotNil(repo)
			got, err := repo.ListAccounts(context.Background(), tt.in, tt.opts...)
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

func TestRepository_ListAccounts_Limits(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	am := testAuthMethods(t, conn, 1)[0]

	accountCount := 10
	_ = testAccounts(t, conn, am.GetScopeId(), am.GetPublicId(), accountCount)

	var tests = []struct {
		name     string
		repoOpts []Option
		listOpts []Option
		wantLen  int
	}{
		{
			name:    "With no limits",
			wantLen: accountCount,
		},
		{
			name:     "With repo limit",
			repoOpts: []Option{WithLimit(3)},
			wantLen:  3,
		},
		{
			name:     "With negative repo limit",
			repoOpts: []Option{WithLimit(-1)},
			wantLen:  accountCount,
		},
		{
			name:     "With List limit",
			listOpts: []Option{WithLimit(3)},
			wantLen:  3,
		},
		{
			name:     "With negative List limit",
			listOpts: []Option{WithLimit(-1)},
			wantLen:  accountCount,
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
			repo, err := NewRepository(rw, rw, wrapper, tt.repoOpts...)
			assert.NoError(err)
			require.NotNil(repo)
			got, err := repo.ListAccounts(context.Background(), am.GetPublicId(), tt.listOpts...)
			require.NoError(err)
			assert.Len(got, tt.wantLen)
		})
	}
}
