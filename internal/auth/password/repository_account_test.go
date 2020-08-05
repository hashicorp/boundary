package password

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hashicorp/watchtower/internal/auth/password/store"
	"github.com/hashicorp/watchtower/internal/db"
	dbassert "github.com/hashicorp/watchtower/internal/db/assert"
	"github.com/hashicorp/watchtower/internal/iam"
	"github.com/hashicorp/watchtower/internal/oplog"
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
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	org, _ := iam.TestScopes(t, conn)
	authMethods := TestAuthMethods(t, conn, org.GetPublicId(), 1)
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
			name: "invalid-username-too-short",
			in: &Account{
				Account: &store.Account{
					AuthMethodId: authMethod.PublicId,
					UserName:     "ka",
				},
			},
			wantIsErr: ErrTooShort,
		},
		{
			name: "invalid-password-too-short",
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
				assert.NoError(db.TestVerifyOplog(t, rw, authAcct.CredentialId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second)))
			}
		})
	}

	t.Run("invalid-duplicate-names", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(rw, rw, wrapper)
		assert.NoError(err)
		require.NotNil(repo)

		org, _ := iam.TestScopes(t, conn)
		authMethods := TestAuthMethods(t, conn, org.GetPublicId(), 1)
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

		org, _ := iam.TestScopes(t, conn)
		authMethods := TestAuthMethods(t, conn, org.GetPublicId(), 2)
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

	org, _ := iam.TestScopes(t, conn)
	authMethod := TestAuthMethods(t, conn, org.GetPublicId(), 1)[0]
	account := TestAccounts(t, conn, authMethod.GetPublicId(), 1)[0]

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

	org, _ := iam.TestScopes(t, conn)
	authMethod := TestAuthMethods(t, conn, org.GetPublicId(), 1)[0]
	account := TestAccounts(t, conn, authMethod.GetPublicId(), 1)[0]

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

	org, _ := iam.TestScopes(t, conn)
	authMethods := TestAuthMethods(t, conn, org.GetPublicId(), 3)
	accounts1 := TestAccounts(t, conn, authMethods[0].GetPublicId(), 3)
	accounts2 := TestAccounts(t, conn, authMethods[1].GetPublicId(), 4)
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

	org, _ := iam.TestScopes(t, conn)
	am := TestAuthMethods(t, conn, org.GetPublicId(), 1)[0]

	accountCount := 10
	_ = TestAccounts(t, conn, am.GetPublicId(), accountCount)

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

func TestRepository_UpdateAccount(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	changeUserName := func(s string) func(*Account) *Account {
		return func(a *Account) *Account {
			a.UserName = s
			return a
		}
	}

	changeName := func(s string) func(*Account) *Account {
		return func(a *Account) *Account {
			a.Name = s
			return a
		}
	}

	changeDescription := func(s string) func(*Account) *Account {
		return func(a *Account) *Account {
			a.Description = s
			return a
		}
	}

	makeNil := func() func(*Account) *Account {
		return func(a *Account) *Account {
			return nil
		}
	}

	makeEmbeddedNil := func() func(*Account) *Account {
		return func(a *Account) *Account {
			return &Account{}
		}
	}

	deletePublicId := func() func(*Account) *Account {
		return func(a *Account) *Account {
			a.PublicId = ""
			return a
		}
	}

	nonExistentPublicId := func() func(*Account) *Account {
		return func(a *Account) *Account {
			a.PublicId = "abcd_OOOOOOOOOO"
			return a
		}
	}

	combine := func(fns ...func(a *Account) *Account) func(*Account) *Account {
		return func(a *Account) *Account {
			for _, fn := range fns {
				a = fn(a)
			}
			return a
		}
	}

	var tests = []struct {
		name      string
		orig      *Account
		chgFn     func(*Account) *Account
		masks     []string
		want      *Account
		wantCount int
		wantIsErr error
	}{
		{
			name: "nil-Account",
			orig: &Account{
				Account: &store.Account{},
			},
			chgFn:     makeNil(),
			masks:     []string{"Name", "Description"},
			wantIsErr: db.ErrNilParameter,
		},
		{
			name: "nil-embedded-Account",
			orig: &Account{
				Account: &store.Account{},
			},
			chgFn:     makeEmbeddedNil(),
			masks:     []string{"Name", "Description"},
			wantIsErr: db.ErrNilParameter,
		},
		{
			name: "no-public-id",
			orig: &Account{
				Account: &store.Account{},
			},
			chgFn:     deletePublicId(),
			masks:     []string{"Name", "Description"},
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "updating-non-existent-Account",
			orig: &Account{
				Account: &store.Account{
					Name: "test-name-repo",
				},
			},
			chgFn:     combine(nonExistentPublicId(), changeName("test-update-name-repo")),
			masks:     []string{"Name"},
			wantIsErr: db.ErrRecordNotFound,
		},
		{
			name: "empty-field-mask",
			orig: &Account{
				Account: &store.Account{
					Name: "test-name-repo",
				},
			},
			chgFn:     changeName("test-update-name-repo"),
			wantIsErr: db.ErrEmptyFieldMask,
		},
		{
			name: "read-only-fields-in-field-mask",
			orig: &Account{
				Account: &store.Account{
					Name: "test-name-repo",
				},
			},
			chgFn:     changeName("test-update-name-repo"),
			masks:     []string{"PublicId", "CreateTime", "UpdateTime", "AuthMethodId"},
			wantIsErr: db.ErrInvalidFieldMask,
		},
		{
			name: "unknown-field-in-field-mask",
			orig: &Account{
				Account: &store.Account{
					Name: "test-name-repo",
				},
			},
			chgFn:     changeName("test-update-name-repo"),
			masks:     []string{"Bilbo"},
			wantIsErr: db.ErrInvalidFieldMask,
		},
		{
			name: "change-name",
			orig: &Account{
				Account: &store.Account{
					Name: "test-name-repo",
				},
			},
			chgFn: changeName("test-update-name-repo"),
			masks: []string{"Name"},
			want: &Account{
				Account: &store.Account{
					Name: "test-update-name-repo",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-description",
			orig: &Account{
				Account: &store.Account{
					Description: "test-description-repo",
				},
			},
			chgFn: changeDescription("test-update-description-repo"),
			masks: []string{"Description"},
			want: &Account{
				Account: &store.Account{
					Description: "test-update-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-name-and-description",
			orig: &Account{
				Account: &store.Account{
					Name:        "test-name-repo",
					Description: "test-description-repo",
				},
			},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("test-update-name-repo")),
			masks: []string{"Name", "Description"},
			want: &Account{
				Account: &store.Account{
					Name:        "test-update-name-repo",
					Description: "test-update-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name: "delete-name",
			orig: &Account{
				Account: &store.Account{
					Name:        "test-name-repo",
					Description: "test-description-repo",
				},
			},
			masks: []string{"Name"},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("")),
			want: &Account{
				Account: &store.Account{
					Description: "test-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name: "delete-description",
			orig: &Account{
				Account: &store.Account{
					Name:        "test-name-repo",
					Description: "test-description-repo",
				},
			},
			masks: []string{"Description"},
			chgFn: combine(changeDescription(""), changeName("test-update-name-repo")),
			want: &Account{
				Account: &store.Account{
					Name: "test-name-repo",
				},
			},
			wantCount: 1,
		},
		{
			name: "do-not-delete-name",
			orig: &Account{
				Account: &store.Account{
					Name:        "test-name-repo",
					Description: "test-description-repo",
				},
			},
			masks: []string{"Description"},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("")),
			want: &Account{
				Account: &store.Account{
					Name:        "test-name-repo",
					Description: "test-update-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name: "do-not-delete-description",
			orig: &Account{
				Account: &store.Account{
					Name:        "test-name-repo",
					Description: "test-description-repo",
				},
			},
			masks: []string{"Name"},
			chgFn: combine(changeDescription(""), changeName("test-update-name-repo")),
			want: &Account{
				Account: &store.Account{
					Name:        "test-update-name-repo",
					Description: "test-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-user-name",
			orig: &Account{
				Account: &store.Account{
					UserName: "kazmierczak",
				},
			},
			chgFn: changeUserName("mothball"),
			masks: []string{"UserName"},
			want: &Account{
				Account: &store.Account{
					UserName: "mothball",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-user-name-mixed-caps",
			orig: &Account{
				Account: &store.Account{
					UserName: "kazmierczak",
				},
			},
			chgFn:     changeUserName("KaZmIeRcZaK"),
			masks:     []string{"UserName"},
			wantIsErr: db.ErrInvalidParameter,
		},
		{
			name: "change-user-name-to-short",
			orig: &Account{
				Account: &store.Account{
					UserName: "kazmierczak",
				},
			},
			chgFn:     changeUserName("ka"),
			masks:     []string{"UserName"},
			wantIsErr: ErrTooShort,
		},
		{
			name: "delete-user-name",
			orig: &Account{
				Account: &store.Account{
					UserName: "kazmierczak",
				},
			},
			chgFn:     changeUserName(""),
			masks:     []string{"UserName"},
			wantIsErr: db.ErrInvalidParameter,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(rw, rw, wrapper)
			assert.NoError(err)
			require.NotNil(repo)

			org, _ := iam.TestScopes(t, conn)
			am := TestAuthMethods(t, conn, org.PublicId, 1)[0]

			tt.orig.AuthMethodId = am.PublicId
			if tt.orig.UserName == "" {
				tt.orig.UserName = "kazmierczak"
			}
			orig, err := repo.CreateAccount(context.Background(), tt.orig)
			assert.NoError(err)
			require.NotNil(orig)

			if tt.chgFn != nil {
				orig = tt.chgFn(orig)
			}
			got, gotCount, err := repo.UpdateAccount(context.Background(), orig, tt.masks)
			if tt.wantIsErr != nil {
				assert.Truef(errors.Is(err, tt.wantIsErr), "want err: %q got: %q", tt.wantIsErr, err)
				assert.Equal(tt.wantCount, gotCount, "row count")
				assert.Nil(got)
				return
			}
			assert.NoError(err)
			assert.Empty(tt.orig.PublicId)
			if tt.wantCount == 0 {
				assert.Equal(tt.wantCount, gotCount, "row count")
				assert.Nil(got)
				return
			}
			require.NotNil(got)
			assertPublicId(t, AccountPrefix, got.PublicId)
			assert.Equal(tt.wantCount, gotCount, "row count")
			assert.NotSame(tt.orig, got)
			assert.Equal(tt.orig.AuthMethodId, got.AuthMethodId)
			dbassert := dbassert.New(t, rw)
			if tt.want.Name == "" {
				dbassert.IsNull(got, "name")
				return
			}
			assert.Equal(tt.want.Name, got.Name)
			if tt.want.Description == "" {
				dbassert.IsNull(got, "description")
				return
			}
			assert.Equal(tt.want.Description, got.Description)
			if tt.wantCount > 0 {
				assert.NoError(db.TestVerifyOplog(t, rw, got.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))
			}
		})
	}

	t.Run("invalid-duplicate-names", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(rw, rw, wrapper)
		assert.NoError(err)
		require.NotNil(repo)

		name := "test-dup-name"
		org, _ := iam.TestScopes(t, conn)
		am := TestAuthMethods(t, conn, org.PublicId, 1)[0]
		acts := TestAccounts(t, conn, am.PublicId, 2)

		aa := acts[0]
		ab := acts[1]

		aa.Name = name
		got1, gotCount1, err := repo.UpdateAccount(context.Background(), aa, []string{"name"})
		assert.NoError(err)
		require.NotNil(got1)
		assert.Equal(name, got1.Name)
		assert.Equal(1, gotCount1, "row count")
		assert.NoError(db.TestVerifyOplog(t, rw, aa.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))

		ab.Name = name
		got2, gotCount2, err := repo.UpdateAccount(context.Background(), ab, []string{"name"})
		assert.Truef(errors.Is(err, db.ErrNotUnique), "want err: %v got: %v", db.ErrNotUnique, err)
		assert.Nil(got2)
		assert.Equal(db.NoRowsAffected, gotCount2, "row count")
		err = db.TestVerifyOplog(t, rw, ab.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
		assert.Error(err)
		assert.True(errors.Is(db.ErrRecordNotFound, err))
	})

	t.Run("valid-duplicate-names-diff-AuthMethods", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(rw, rw, wrapper)
		assert.NoError(err)
		require.NotNil(repo)

		org, _ := iam.TestScopes(t, conn)
		ams := TestAuthMethods(t, conn, org.PublicId, 2)

		ama := ams[0]
		amb := ams[1]

		in := &Account{
			Account: &store.Account{
				Name: "test-name-repo",
			},
		}
		in2 := in.clone()

		in.AuthMethodId = ama.PublicId
		in.UserName = "kazmierczak"
		got, err := repo.CreateAccount(context.Background(), in)
		assert.NoError(err)
		require.NotNil(got)
		assertPublicId(t, AccountPrefix, got.PublicId)
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)

		in2.AuthMethodId = amb.PublicId
		in2.UserName = "kazmierczak2"
		in2.Name = "first-name"
		got2, err := repo.CreateAccount(context.Background(), in2)
		assert.NoError(err)
		require.NotNil(got2)
		got2.Name = got.Name
		got3, gotCount3, err := repo.UpdateAccount(context.Background(), got2, []string{"name"})
		assert.NoError(err)
		require.NotNil(got3)
		assert.NotSame(got2, got3)
		assert.Equal(got.Name, got3.Name)
		assert.Equal(got2.Description, got3.Description)
		assert.Equal(1, gotCount3, "row count")
		assert.NoError(db.TestVerifyOplog(t, rw, got2.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))
	})

	t.Run("change-authmethod-id", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(rw, rw, wrapper)
		assert.NoError(err)
		require.NotNil(repo)

		org, _ := iam.TestScopes(t, conn)
		ams := TestAuthMethods(t, conn, org.PublicId, 2)

		ama := ams[0]
		amb := ams[1]

		aa := TestAccounts(t, conn, ama.PublicId, 1)[0]
		ab := TestAccounts(t, conn, amb.PublicId, 1)[0]

		assert.NotEqual(aa.AuthMethodId, ab.AuthMethodId)
		orig := aa.clone()

		aa.AuthMethodId = ab.AuthMethodId
		assert.Equal(aa.AuthMethodId, ab.AuthMethodId)

		got1, gotCount1, err := repo.UpdateAccount(context.Background(), aa, []string{"name"})

		assert.NoError(err)
		require.NotNil(got1)
		assert.Equal(orig.AuthMethodId, got1.AuthMethodId)
		assert.Equal(1, gotCount1, "row count")
		assert.NoError(db.TestVerifyOplog(t, rw, aa.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))
	})
}
