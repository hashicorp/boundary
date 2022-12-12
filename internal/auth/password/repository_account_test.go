package password

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/auth/password/store"
	"github.com/hashicorp/boundary/internal/db"
	dbassert "github.com/hashicorp/boundary/internal/db/assert"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/intglobals"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckLoginName(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"", false},
		{" leading-spaces", false},
		{"trailing-spaces ", false},
		{"contains spaces", false},
		{"NotLowerCase", false},
		{"valid.loginname", true},
		{"valid-loginname", true},
		{"validloginname", true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.in, func(t *testing.T) {
			assert.Equal(t, tt.want, validLoginName(tt.in))
		})
	}
}

func TestRepository_CreateAccount(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iamRepo)

	authMethods := TestAuthMethods(t, conn, org.GetPublicId(), 1)
	authMethod := authMethods[0]

	tests := []struct {
		name       string
		in         *Account
		opts       []Option
		want       *Account
		wantIsErr  errors.Code
		wantErrMsg string
	}{
		{
			name:       "nil-Account",
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "password.(Repository).CreateAccount: missing Account: parameter violation: error #100",
		},
		{
			name:       "nil-embedded-Account",
			in:         &Account{},
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "password.(Repository).CreateAccount: missing embedded Account: parameter violation: error #100",
		},
		{
			name: "invalid-no-scope-id",
			in: &Account{
				Account: &store.Account{},
			},
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "password.(Repository).CreateAccount: missing auth method id: parameter violation: error #100",
		},
		{
			name: "invalid-public-id-set",
			in: &Account{
				Account: &store.Account{
					AuthMethodId: authMethod.PublicId,
					PublicId:     "hcst_OOOOOOOOOO",
				},
			},
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "password.(Repository).CreateAccount: public id must be empty: parameter violation: error #100",
		},
		{
			name: "invalid-loginname-uppercase",
			in: &Account{
				Account: &store.Account{
					AuthMethodId: authMethod.PublicId,
					LoginName:    "KaZmiErcZak11",
				},
			},
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "password.(Repository).CreateAccount: login name must be all-lowercase alphanumeric, period or hyphen. got: KaZmiErcZak11: parameter violation: error #100",
		},
		{
			name: "invalid-loginname-leading-space",
			in: &Account{
				Account: &store.Account{
					AuthMethodId: authMethod.PublicId,
					LoginName:    " kazmierczak12",
				},
			},
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "password.(Repository).CreateAccount: login name must be all-lowercase alphanumeric, period or hyphen. got:  kazmierczak12: parameter violation: error #100",
		},
		{
			name: "invalid-loginname-trailing-space",
			in: &Account{
				Account: &store.Account{
					AuthMethodId: authMethod.PublicId,
					LoginName:    "kazmierczak13 ",
				},
			},
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "password.(Repository).CreateAccount: login name must be all-lowercase alphanumeric, period or hyphen. got: kazmierczak13 : parameter violation: error #100",
		},
		{
			name: "invalid-loginname-space-in-name",
			in: &Account{
				Account: &store.Account{
					AuthMethodId: authMethod.PublicId,
					LoginName:    "kazmier czak14",
				},
			},
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "password.(Repository).CreateAccount: login name must be all-lowercase alphanumeric, period or hyphen. got: kazmier czak14: parameter violation: error #100",
		},
		{
			name: "invalid-loginname-too-short",
			in: &Account{
				Account: &store.Account{
					AuthMethodId: authMethod.PublicId,
					LoginName:    "ka",
				},
			},
			wantIsErr:  errors.TooShort,
			wantErrMsg: "password.(Repository).CreateAccount: username: ka, must be longer than 3: integrity violation: error #113",
		},
		{
			name: "invalid-password-too-short",
			in: &Account{
				Account: &store.Account{
					AuthMethodId: authMethod.PublicId,
					LoginName:    "kazmierczak123",
				},
			},
			opts: []Option{
				WithPassword("a"),
			},
			wantIsErr:  errors.PasswordTooShort,
			wantErrMsg: "password.(Repository).CreateAccount: must be longer than 8: password violation: error #200",
		},
		{
			name: "valid-no-options",
			in: &Account{
				Account: &store.Account{
					AuthMethodId: authMethod.PublicId,
					LoginName:    "kazmierczak",
				},
			},
			want: &Account{
				Account: &store.Account{
					AuthMethodId: authMethod.PublicId,
					LoginName:    "kazmierczak",
				},
			},
		},
		{
			name: "valid-with-name",
			in: &Account{
				Account: &store.Account{
					AuthMethodId: authMethod.PublicId,
					Name:         "test-name-repo",
					LoginName:    "kazmierczak1",
				},
			},
			want: &Account{
				Account: &store.Account{
					AuthMethodId: authMethod.PublicId,
					Name:         "test-name-repo",
					LoginName:    "kazmierczak1",
				},
			},
		},
		{
			name: "valid-with-description",
			in: &Account{
				Account: &store.Account{
					AuthMethodId: authMethod.PublicId,
					Description:  ("test-description-repo"),
					LoginName:    "kazmierczak2",
				},
			},
			want: &Account{
				Account: &store.Account{
					AuthMethodId: authMethod.PublicId,
					Description:  ("test-description-repo"),
					LoginName:    "kazmierczak2",
				},
			},
		},
		{
			name: "valid-with-password",
			in: &Account{
				Account: &store.Account{
					AuthMethodId: authMethod.PublicId,
					LoginName:    "kazmierczak3",
				},
			},
			opts: []Option{
				WithPassword("1234567890"),
			},
			want: &Account{
				Account: &store.Account{
					AuthMethodId: authMethod.PublicId,
					LoginName:    "kazmierczak3",
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(rw, rw, kms)
			assert.NoError(err)
			require.NotNil(repo)
			got, err := repo.CreateAccount(context.Background(), org.GetPublicId(), tt.in, tt.opts...)
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "Unexpected error %s", err)
				assert.Equal(tt.wantErrMsg, err.Error())
				return
			}
			require.NoError(err)
			assert.Empty(tt.in.PublicId)
			require.NotNil(got)
			assertPublicId(t, intglobals.NewPasswordAccountPrefix, got.PublicId)
			assert.NotSame(tt.in, got)
			assert.Equal(tt.want.Name, got.Name)
			assert.Equal(tt.want.Description, got.Description)
			assert.Equal(got.CreateTime, got.UpdateTime)

			assert.NoError(db.TestVerifyOplog(t, rw, got.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second)))

			opts := GetOpts(tt.opts...)
			if opts.withPassword {
				authAcct, err := repo.Authenticate(context.Background(), org.GetPublicId(), tt.in.AuthMethodId, tt.in.LoginName, opts.password)
				require.NoError(err)
				assert.NoError(db.TestVerifyOplog(t, rw, authAcct.CredentialId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second)))
			}
		})
	}
}

func TestRepository_CreateAccount_DuplicateNames(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)

	t.Run("invalid-duplicate-names", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(rw, rw, kms)
		assert.NoError(err)
		require.NotNil(repo)

		org, _ := iam.TestScopes(t, iamRepo)
		authMethods := TestAuthMethods(t, conn, org.GetPublicId(), 1)
		authMethod := authMethods[0]

		in := &Account{
			Account: &store.Account{
				AuthMethodId: authMethod.GetPublicId(),
				Name:         "test-name-repo",
				LoginName:    "kazmierczak3",
			},
		}

		got, err := repo.CreateAccount(context.Background(), org.GetPublicId(), in)
		require.NoError(err)
		require.NotNil(got)
		assertPublicId(t, intglobals.NewPasswordAccountPrefix, got.PublicId)
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)
		assert.Equal(got.CreateTime, got.UpdateTime)

		got2, err := repo.CreateAccount(context.Background(), org.GetPublicId(), in)
		assert.Truef(errors.Match(errors.T(errors.NotUnique), err), "Unexpected error %s", err)
		assert.Nil(got2)
	})

	t.Run("valid-duplicate-names-diff-parents", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(rw, rw, kms)
		assert.NoError(err)
		require.NotNil(repo)

		org, _ := iam.TestScopes(t, iamRepo)
		authMethods := TestAuthMethods(t, conn, org.GetPublicId(), 2)
		authMethoda, authMethodb := authMethods[0], authMethods[1]
		in := &Account{
			Account: &store.Account{
				Name:      "test-name-repo",
				LoginName: "kazmierczak4",
			},
		}
		in2 := in.clone()

		in.AuthMethodId = authMethoda.GetPublicId()
		got, err := repo.CreateAccount(context.Background(), org.GetPublicId(), in)
		require.NoError(err)
		require.NotNil(got)
		assertPublicId(t, intglobals.NewPasswordAccountPrefix, got.PublicId)
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)
		assert.Equal(got.CreateTime, got.UpdateTime)

		in2.AuthMethodId = authMethodb.GetPublicId()
		got2, err := repo.CreateAccount(context.Background(), org.GetPublicId(), in2)
		assert.NoError(err)
		require.NotNil(got2)
		assertPublicId(t, intglobals.NewPasswordAccountPrefix, got2.PublicId)
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

	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iamRepo)

	authMethod := TestAuthMethods(t, conn, org.GetPublicId(), 1)[0]
	account := TestAccount(t, conn, authMethod.GetPublicId(), "name1")

	newAcctId, err := newAccountId()
	require.NoError(t, err)
	tests := []struct {
		name       string
		in         string
		want       *Account
		wantIsErr  errors.Code
		wantErrMsg string
	}{
		{
			name:       "With no public id",
			wantIsErr:  errors.InvalidPublicId,
			wantErrMsg: "password.(Repository).LookupAccount: missing public id: parameter violation: error #102",
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
			repo, err := NewRepository(rw, rw, kms)
			assert.NoError(err)
			require.NotNil(repo)
			got, err := repo.LookupAccount(context.Background(), tt.in)
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "Unexpected error %s", err)
				assert.Equal(tt.wantErrMsg, err.Error())
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

	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iamRepo)

	authMethod := TestAuthMethods(t, conn, org.GetPublicId(), 1)[0]
	account := TestAccount(t, conn, authMethod.GetPublicId(), "name1")

	newAcctId, err := newAccountId()
	require.NoError(t, err)
	tests := []struct {
		name       string
		in         string
		want       int
		wantIsErr  errors.Code
		wantErrMsg string
	}{
		{
			name:       "With no public id",
			wantIsErr:  errors.InvalidPublicId,
			wantErrMsg: "password.(Repository).DeleteAccount: missing public id: parameter violation: error #102",
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
			repo, err := NewRepository(rw, rw, kms)
			assert.NoError(err)
			require.NotNil(repo)
			got, err := repo.DeleteAccount(context.Background(), org.GetPublicId(), tt.in)
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "Unexpected error %s", err)
				assert.Equal(tt.wantErrMsg, err.Error())
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

	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iamRepo)

	authMethods := TestAuthMethods(t, conn, org.GetPublicId(), 3)
	accounts1 := TestMultipleAccounts(t, conn, authMethods[0].GetPublicId(), 3)
	accounts2 := TestMultipleAccounts(t, conn, authMethods[1].GetPublicId(), 4)
	_ = accounts2

	tests := []struct {
		name       string
		in         string
		opts       []Option
		want       []*Account
		wantIsErr  errors.Code
		wantErrMsg string
	}{
		{
			name:       "With no auth method id",
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "password.(Repository).ListAccounts: missing auth method id: parameter violation: error #100",
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
			repo, err := NewRepository(rw, rw, kms)
			assert.NoError(err)
			require.NotNil(repo)
			got, err := repo.ListAccounts(context.Background(), tt.in, tt.opts...)
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "Unexpected error %s", err)
				assert.Equal(tt.wantErrMsg, err.Error())
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

	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iamRepo)

	am := TestAuthMethods(t, conn, org.GetPublicId(), 1)[0]

	accountCount := 10
	_ = TestMultipleAccounts(t, conn, am.GetPublicId(), accountCount)

	tests := []struct {
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
			repo, err := NewRepository(rw, rw, kms, tt.repoOpts...)
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
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	ctx := context.Background()

	changeLoginName := func(s string) func(*Account) *Account {
		return func(a *Account) *Account {
			a.LoginName = s
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

	tests := []struct {
		name       string
		orig       *Account
		chgFn      func(*Account) *Account
		masks      []string
		want       *Account
		wantCount  int
		wantIsErr  errors.Code
		wantErrMsg string
	}{
		{
			name: "nil-Account",
			orig: &Account{
				Account: &store.Account{},
			},
			chgFn:      makeNil(),
			masks:      []string{"Name", "Description"},
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "password.(Repository).UpdateAccount: missing Account: parameter violation: error #100",
		},
		{
			name: "nil-embedded-Account",
			orig: &Account{
				Account: &store.Account{},
			},
			chgFn:      makeEmbeddedNil(),
			masks:      []string{"Name", "Description"},
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "password.(Repository).UpdateAccount: missing embedded Account: parameter violation: error #100",
		},
		{
			name: "no-public-id",
			orig: &Account{
				Account: &store.Account{},
			},
			chgFn:      deletePublicId(),
			masks:      []string{"Name", "Description"},
			wantIsErr:  errors.InvalidPublicId,
			wantErrMsg: "password.(Repository).UpdateAccount: missing public id: parameter violation: error #102",
		},
		{
			name: "updating-non-existent-Account",
			orig: &Account{
				Account: &store.Account{
					Name: "test-name-repo",
				},
			},
			chgFn:      combine(nonExistentPublicId(), changeName("test-update-name-repo")),
			masks:      []string{"Name"},
			wantIsErr:  errors.RecordNotFound,
			wantErrMsg: "password.(Repository).UpdateAccount: abcd_OOOOOOOOOO: db.DoTx: password.(Repository).UpdateAccount: db.Update: record not found, search issue: error #1100: dbw.Update: dbw.lookupAfterWrite: dbw.LookupById: record not found",
		},
		{
			name: "empty-field-mask",
			orig: &Account{
				Account: &store.Account{
					Name: "test-name-repo",
				},
			},
			chgFn:      changeName("test-update-name-repo"),
			wantIsErr:  errors.EmptyFieldMask,
			wantErrMsg: "password.(Repository).UpdateAccount: missing field mask: parameter violation: error #104",
		},
		{
			name: "read-only-fields-in-field-mask",
			orig: &Account{
				Account: &store.Account{
					Name: "test-name-repo",
				},
			},
			chgFn:      changeName("test-update-name-repo"),
			masks:      []string{"PublicId", "CreateTime", "UpdateTime", "AuthMethodId"},
			wantIsErr:  errors.InvalidFieldMask,
			wantErrMsg: "password.(Repository).UpdateAccount: PublicId: parameter violation: error #103",
		},
		{
			name: "unknown-field-in-field-mask",
			orig: &Account{
				Account: &store.Account{
					Name: "test-name-repo",
				},
			},
			chgFn:      changeName("test-update-name-repo"),
			masks:      []string{"Bilbo"},
			wantIsErr:  errors.InvalidFieldMask,
			wantErrMsg: "password.(Repository).UpdateAccount: Bilbo: parameter violation: error #103",
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
			name: "change-login-name",
			orig: &Account{
				Account: &store.Account{
					LoginName: "kazmierczak",
				},
			},
			chgFn: changeLoginName("mothball"),
			masks: []string{"LoginName"},
			want: &Account{
				Account: &store.Account{
					LoginName: "mothball",
				},
			},
			wantCount: 1,
		},
		{
			name: "change-login-name-mixed-caps",
			orig: &Account{
				Account: &store.Account{
					LoginName: "kazmierczak",
				},
			},
			chgFn:      changeLoginName("KaZmIeRcZaK"),
			masks:      []string{"LoginName"},
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "password.(Repository).UpdateAccount: invalid username: must be all-lowercase alphanumeric, period or hyphen, got KaZmIeRcZaK: parameter violation: error #100",
		},
		{
			name: "change-login-name-to-short",
			orig: &Account{
				Account: &store.Account{
					LoginName: "kazmierczak",
				},
			},
			chgFn:      changeLoginName("ka"),
			masks:      []string{"LoginName"},
			wantIsErr:  errors.TooShort,
			wantErrMsg: "password.(Repository).UpdateAccount: username: ka, must be longer than 3: integrity violation: error #113",
		},
		{
			name: "delete-login-name",
			orig: &Account{
				Account: &store.Account{
					LoginName: "kazmierczak",
				},
			},
			chgFn:      changeLoginName(""),
			masks:      []string{"LoginName"},
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "password.(Repository).UpdateAccount: invalid username: must be all-lowercase alphanumeric, period or hyphen, got : parameter violation: error #100",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(rw, rw, kms)
			assert.NoError(err)
			require.NotNil(repo)

			org, _ := iam.TestScopes(t, iamRepo)
			am := TestAuthMethods(t, conn, org.PublicId, 1)[0]

			tt.orig.AuthMethodId = am.PublicId
			if tt.orig.LoginName == "" {
				tt.orig.LoginName = "kazmierczak"
			}
			orig, err := repo.CreateAccount(context.Background(), org.GetPublicId(), tt.orig)
			assert.NoError(err)
			require.NotNil(orig)

			if tt.chgFn != nil {
				orig = tt.chgFn(orig)
			}
			got, gotCount, err := repo.UpdateAccount(context.Background(), org.GetPublicId(), orig, 1, tt.masks)
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "want err: %q got: %q", tt.wantIsErr, err)
				assert.Equal(tt.wantErrMsg, err.Error())
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
			assertPublicId(t, intglobals.NewPasswordAccountPrefix, got.PublicId)
			assert.Equal(tt.wantCount, gotCount, "row count")
			assert.NotSame(tt.orig, got)
			assert.Equal(tt.orig.AuthMethodId, got.AuthMethodId)
			underlyingDB, err := conn.SqlDB(ctx)
			require.NoError(err)
			dbassert := dbassert.New(t, underlyingDB)
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
}

func TestRepository_UpdateAccount_DupeNames(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)

	t.Run("invalid-duplicate-names", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(rw, rw, kms)
		assert.NoError(err)
		require.NotNil(repo)

		name := "test-dup-name"
		org, _ := iam.TestScopes(t, iamRepo)
		am := TestAuthMethods(t, conn, org.PublicId, 1)[0]
		acts := TestMultipleAccounts(t, conn, am.PublicId, 2)

		aa := acts[0]
		ab := acts[1]

		aa.Name = name
		got1, gotCount1, err := repo.UpdateAccount(context.Background(), org.GetPublicId(), aa, 1, []string{"name"})
		assert.NoError(err)
		require.NotNil(got1)
		assert.Equal(name, got1.Name)
		assert.Equal(1, gotCount1, "row count")
		assert.NoError(db.TestVerifyOplog(t, rw, aa.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))

		ab.Name = name
		got2, gotCount2, err := repo.UpdateAccount(context.Background(), org.GetPublicId(), ab, 1, []string{"name"})
		assert.Truef(errors.Match(errors.T(errors.NotUnique), err), "Unexpected error %s", err)
		assert.Nil(got2)
		assert.Equal(db.NoRowsAffected, gotCount2, "row count")
		err = db.TestVerifyOplog(t, rw, ab.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
		assert.Error(err)
		assert.True(errors.IsNotFoundError(err))
	})

	t.Run("valid-duplicate-names-diff-AuthMethods", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(rw, rw, kms)
		assert.NoError(err)
		require.NotNil(repo)

		org, _ := iam.TestScopes(t, iamRepo)
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
		in.LoginName = "kazmierczak"
		got, err := repo.CreateAccount(context.Background(), org.GetPublicId(), in)
		assert.NoError(err)
		require.NotNil(got)
		assertPublicId(t, intglobals.NewPasswordAccountPrefix, got.PublicId)
		assert.NotSame(in, got)
		assert.Equal(in.Name, got.Name)
		assert.Equal(in.Description, got.Description)

		in2.AuthMethodId = amb.PublicId
		in2.LoginName = "kazmierczak2"
		in2.Name = "first-name"
		got2, err := repo.CreateAccount(context.Background(), org.GetPublicId(), in2)
		assert.NoError(err)
		require.NotNil(got2)
		got2.Name = got.Name
		got3, gotCount3, err := repo.UpdateAccount(context.Background(), org.GetPublicId(), got2, 1, []string{"name"})
		assert.NoError(err)
		require.NotNil(got3)
		assert.NotSame(got2, got3)
		assert.Equal(got.Name, got3.Name)
		assert.Equal(got2.Description, got3.Description)
		assert.Equal(1, gotCount3, "row count")
		assert.NoError(db.TestVerifyOplog(t, rw, got2.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))
	})

	t.Run("invalid-duplicate-loginnames", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(rw, rw, kms)
		assert.NoError(err)
		require.NotNil(repo)

		loginName := "kazmierczak12"
		org, _ := iam.TestScopes(t, iamRepo)
		am := TestAuthMethods(t, conn, org.PublicId, 1)[0]
		acts := TestMultipleAccounts(t, conn, am.PublicId, 2)

		aa := acts[0]
		ab := acts[1]

		aa.LoginName = loginName
		got1, gotCount1, err := repo.UpdateAccount(context.Background(), org.GetPublicId(), aa, 1, []string{"LoginName"})
		assert.NoError(err)
		require.NotNil(got1)
		assert.Equal(loginName, got1.LoginName)
		assert.Equal(1, gotCount1, "row count")
		assert.NoError(db.TestVerifyOplog(t, rw, aa.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))

		ab.LoginName = loginName
		got2, gotCount2, err := repo.UpdateAccount(context.Background(), org.GetPublicId(), ab, 1, []string{"LoginName"})
		assert.Truef(errors.Match(errors.T(errors.NotUnique), err), "Unexpected error %s", err)
		assert.Nil(got2)
		assert.Equal(db.NoRowsAffected, gotCount2, "row count")
		err = db.TestVerifyOplog(t, rw, ab.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
		assert.Error(err)
		assert.True(errors.IsNotFoundError(err))
	})

	t.Run("valid-duplicate-loginnames-diff-AuthMethods", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(rw, rw, kms)
		assert.NoError(err)
		require.NotNil(repo)

		org, _ := iam.TestScopes(t, iamRepo)
		ams := TestAuthMethods(t, conn, org.PublicId, 2)

		ama := ams[0]
		amb := ams[1]

		in := &Account{
			Account: &store.Account{
				LoginName: "kazmierczak",
			},
		}
		in2 := in.clone()

		in.AuthMethodId = ama.PublicId
		got, err := repo.CreateAccount(context.Background(), org.GetPublicId(), in)
		assert.NoError(err)
		require.NotNil(got)
		assertPublicId(t, intglobals.NewPasswordAccountPrefix, got.PublicId)
		assert.NotSame(in, got)
		assert.Equal(in.LoginName, got.LoginName)

		in2.AuthMethodId = amb.PublicId
		in2.LoginName = "kazmierczak2"
		got2, err := repo.CreateAccount(context.Background(), org.GetPublicId(), in2)
		assert.NoError(err)
		require.NotNil(got2)
		got2.LoginName = got.LoginName
		got3, gotCount3, err := repo.UpdateAccount(context.Background(), org.GetPublicId(), got2, 1, []string{"LoginName"})
		assert.NoError(err)
		require.NotNil(got3)
		assert.NotSame(got2, got3)
		assert.Equal(got.LoginName, got3.LoginName)
		assert.Equal(1, gotCount3, "row count")
		assert.NoError(db.TestVerifyOplog(t, rw, got2.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))
	})

	t.Run("change-authmethod-id", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(rw, rw, kms)
		assert.NoError(err)
		require.NotNil(repo)

		org, _ := iam.TestScopes(t, iamRepo)
		ams := TestAuthMethods(t, conn, org.PublicId, 2)

		ama := ams[0]
		amb := ams[1]

		aa := TestMultipleAccounts(t, conn, ama.PublicId, 1)[0]
		ab := TestMultipleAccounts(t, conn, amb.PublicId, 1)[0]

		assert.NotEqual(aa.AuthMethodId, ab.AuthMethodId)
		orig := aa.clone()

		aa.AuthMethodId = ab.AuthMethodId
		assert.Equal(aa.AuthMethodId, ab.AuthMethodId)

		got1, gotCount1, err := repo.UpdateAccount(context.Background(), org.GetPublicId(), aa, 1, []string{"name"})

		assert.NoError(err)
		require.NotNil(got1)
		assert.Equal(orig.AuthMethodId, got1.AuthMethodId)
		assert.Equal(1, gotCount1, "row count")
		assert.NoError(db.TestVerifyOplog(t, rw, aa.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))
	})
}
