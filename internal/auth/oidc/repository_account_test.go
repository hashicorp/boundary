package oidc

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/auth/oidc/store"
	"github.com/hashicorp/boundary/internal/db"
	dbassert "github.com/hashicorp/boundary/internal/db/assert"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_LookupAccount(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iamRepo)

	ctx := context.Background()
	databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	authMethod := TestAuthMethod(
		t, conn, databaseWrapper, org.PublicId, ActivePrivateState,
		TestConvertToUrls(t, "https://www.alice.com")[0],
		"alice-rp", "fido",
		WithSigningAlgs(RS256),
		WithCallbackUrls(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)
	account := TestAccount(t, conn, authMethod.PublicId, TestConvertToUrls(t, authMethod.DiscoveryUrl)[0], "create-success")

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
			wantErrMsg: "oidc.(Repository).LookupAccount: missing public id: parameter violation: error #102",
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
			repo, err := NewRepository(rw, rw, kmsCache)
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

	ctx := context.Background()
	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iamRepo)

	databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	authMethod := TestAuthMethod(
		t, conn, databaseWrapper, org.PublicId, ActivePrivateState,
		TestConvertToUrls(t, "https://www.alice.com")[0],
		"alice-rp", "fido",
		WithSigningAlgs(RS256),
		WithCallbackUrls(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)
	account := TestAccount(t, conn, authMethod.PublicId, TestConvertToUrls(t, authMethod.DiscoveryUrl)[0], "create-success")

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
			wantErrMsg: "oidc.(Repository).DeleteAccount: missing public id: parameter violation: error #102",
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
			repo, err := NewRepository(rw, rw, kmsCache)
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

	ctx := context.Background()
	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iamRepo)

	databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	authMethod1 := TestAuthMethod(
		t, conn, databaseWrapper, org.PublicId, ActivePrivateState,
		TestConvertToUrls(t, "https://www.alice1.com")[0],
		"alice-rp", "fido",
		WithSigningAlgs(RS256),
		WithCallbackUrls(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)
	authMethod2 := TestAuthMethod(
		t, conn, databaseWrapper, org.PublicId, ActivePrivateState,
		TestConvertToUrls(t, "https://www.alice2.com")[0],
		"alice-rp", "fido",
		WithSigningAlgs(RS256),
		WithCallbackUrls(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)
	authMethod3 := TestAuthMethod(
		t, conn, databaseWrapper, org.PublicId, ActivePrivateState,
		TestConvertToUrls(t, "https://www.alice3.com")[0],
		"alice-rp", "fido",
		WithSigningAlgs(RS256),
		WithCallbackUrls(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)
	accounts1 := []*Account{
		TestAccount(t, conn, authMethod1.PublicId, TestConvertToUrls(t, authMethod1.DiscoveryUrl)[0], "create-success"),
		TestAccount(t, conn, authMethod1.PublicId, TestConvertToUrls(t, authMethod1.DiscoveryUrl)[0], "create-success2"),
		TestAccount(t, conn, authMethod1.PublicId, TestConvertToUrls(t, authMethod1.DiscoveryUrl)[0], "create-success3"),
	}
	accounts2 := []*Account{
		TestAccount(t, conn, authMethod2.PublicId, TestConvertToUrls(t, authMethod2.DiscoveryUrl)[0], "create-success"),
		TestAccount(t, conn, authMethod2.PublicId, TestConvertToUrls(t, authMethod2.DiscoveryUrl)[0], "create-success2"),
		TestAccount(t, conn, authMethod2.PublicId, TestConvertToUrls(t, authMethod2.DiscoveryUrl)[0], "create-success3"),
	}
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
			wantErrMsg: "oidc.(Repository).ListAccounts: missing auth method id: parameter violation: error #100",
		},
		{
			name: "With no accounts id",
			in:   authMethod3.GetPublicId(),
			want: []*Account{},
		},
		{
			name: "With first auth method id",
			in:   authMethod1.GetPublicId(),
			want: accounts1,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(rw, rw, kmsCache)
			assert.NoError(err)
			require.NotNil(repo)
			got, err := repo.ListAccounts(context.Background(), tt.in, tt.opts...)
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "Unexpected error %s", err)
				assert.Equal(tt.wantErrMsg, err.Error())
				return
			}
			require.NoError(err)

			sort.Slice(got, func(i, j int) bool {
				return strings.Compare(got[i].SubjectId, got[j].SubjectId) < 0
			})
			assert.EqualValues(tt.want, got)
		})
	}
}

func TestRepository_ListAccounts_Limits(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	ctx := context.Background()
	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iamRepo)

	databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	am := TestAuthMethod(
		t, conn, databaseWrapper, org.PublicId, ActivePrivateState,
		TestConvertToUrls(t, "https://www.alice1.com")[0],
		"alice-rp", "fido",
		WithSigningAlgs(RS256),
		WithCallbackUrls(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)

	accountCount := 10
	for i := 0; i < accountCount; i++ {
		TestAccount(t, conn, am.PublicId, TestConvertToUrls(t, am.DiscoveryUrl)[0], fmt.Sprintf("create-success-%d", i))
	}

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
			repo, err := NewRepository(rw, rw, kmsCache, tt.repoOpts...)
			assert.NoError(err)
			require.NotNil(repo)
			got, err := repo.ListAccounts(context.Background(), am.GetPublicId(), tt.listOpts...)
			require.NoError(err)
			assert.Len(got, tt.wantLen)
		})
	}
}

func TestRepository_UpdateAccount(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)

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
			wantErrMsg: "oidc.(Repository).UpdateAccount: missing Account: parameter violation: error #100",
		},
		{
			name: "nil-embedded-Account",
			orig: &Account{
				Account: &store.Account{},
			},
			chgFn:      makeEmbeddedNil(),
			masks:      []string{"Name", "Description"},
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "oidc.(Repository).UpdateAccount: missing embedded Account: parameter violation: error #100",
		},
		{
			name: "no-public-id",
			orig: &Account{
				Account: &store.Account{},
			},
			chgFn:      deletePublicId(),
			masks:      []string{"Name", "Description"},
			wantIsErr:  errors.InvalidPublicId,
			wantErrMsg: "oidc.(Repository).UpdateAccount: missing public id: parameter violation: error #102",
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
			wantErrMsg: "oidc.(Repository).UpdateAccount: abcd_OOOOOOOOOO: db.DoTx: oidc.(Repository).UpdateAccount: db.Update: db.lookupAfterWrite: db.LookupById: record not found, search issue: error #1100",
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
			wantErrMsg: "oidc.(Repository).UpdateAccount: missing field mask: parameter violation: error #104",
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
			wantErrMsg: "oidc.(Repository).UpdateAccount: PublicId: parameter violation: error #103",
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
			wantErrMsg: "oidc.(Repository).UpdateAccount: Bilbo: parameter violation: error #103",
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
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(rw, rw, kmsCache)
			assert.NoError(err)
			require.NotNil(repo)

			org, _ := iam.TestScopes(t, iamRepo)
			databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
			require.NoError(err)
			am := TestAuthMethod(
				t, conn, databaseWrapper, org.PublicId, ActivePrivateState,
				TestConvertToUrls(t, "https://www.alice.com")[0],
				"alice-rp", "fido",
				WithSigningAlgs(RS256),
				WithCallbackUrls(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
			)

			orig := TestAccount(t, conn, am.PublicId, TestConvertToUrls(t, am.DiscoveryUrl)[0], "create-success",
				WithName(tt.orig.GetName()), WithDescription(tt.orig.GetDescription()))

			tt.orig.AuthMethodId = am.PublicId
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
			assertPublicId(t, AccountPrefix, got.PublicId)
			assert.Equal(tt.wantCount, gotCount, "row count")
			assert.NotSame(tt.orig, got)
			assert.Equal(tt.orig.AuthMethodId, got.AuthMethodId)
			dbassert := dbassert.New(t, conn.DB())
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
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)

	t.Run("invalid-duplicate-names", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(rw, rw, kmsCache)
		assert.NoError(err)
		require.NotNil(repo)

		name := "test-dup-name"
		org, _ := iam.TestScopes(t, iamRepo)
		databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
		require.NoError(err)

		am := TestAuthMethod(
			t, conn, databaseWrapper, org.PublicId, ActivePrivateState,
			TestConvertToUrls(t, "https://www.alice.com")[0],
			"alice-rp", "fido",
			WithSigningAlgs(RS256),
			WithCallbackUrls(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
		)
		aa := TestAccount(t, conn, am.PublicId, TestConvertToUrls(t, am.DiscoveryUrl)[0], "create-success1")
		ab := TestAccount(t, conn, am.PublicId, TestConvertToUrls(t, am.DiscoveryUrl)[0], "create-success2")

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
		repo, err := NewRepository(rw, rw, kmsCache)
		assert.NoError(err)
		require.NotNil(repo)

		org, _ := iam.TestScopes(t, iamRepo)
		databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
		require.NoError(err)

		ama := TestAuthMethod(
			t, conn, databaseWrapper, org.PublicId, ActivePrivateState,
			TestConvertToUrls(t, "https://www.alice.com")[0],
			"alice-rp", "fido",
			WithSigningAlgs(RS256),
			WithCallbackUrls(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
		)
		aa := TestAccount(t, conn, ama.PublicId, TestConvertToUrls(t, ama.DiscoveryUrl)[0], "create-success1",
			WithName("test-name-aa"))

		amb := TestAuthMethod(
			t, conn, databaseWrapper, org.PublicId, ActivePrivateState,
			TestConvertToUrls(t, "https://www.alice2.com")[0],
			"alice-rp", "fido2",
			WithSigningAlgs(RS256),
			WithCallbackUrls(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
		)
		ab := TestAccount(t, conn, amb.PublicId, TestConvertToUrls(t, amb.DiscoveryUrl)[0], "create-success2",
			WithName("test-name-ab"))

		ab.Name = aa.Name
		got3, gotCount3, err := repo.UpdateAccount(context.Background(), org.GetPublicId(), ab, 1, []string{"name"})
		assert.NoError(err)
		require.NotNil(got3)
		assert.NotSame(ab, got3)
		assert.Equal(aa.Name, got3.Name)
		assert.Equal(1, gotCount3, "row count")
		assert.NoError(db.TestVerifyOplog(t, rw, ab.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))
	})

	t.Run("change-authmethod-id", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		repo, err := NewRepository(rw, rw, kmsCache)
		assert.NoError(err)
		require.NotNil(repo)

		org, _ := iam.TestScopes(t, iamRepo)
		databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
		require.NoError(err)

		ama := TestAuthMethod(
			t, conn, databaseWrapper, org.PublicId, ActivePrivateState,
			TestConvertToUrls(t, "https://www.alice.com")[0],
			"alice-rp", "fido",
			WithSigningAlgs(RS256),
			WithCallbackUrls(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
		)
		aa := TestAccount(t, conn, ama.PublicId, TestConvertToUrls(t, ama.DiscoveryUrl)[0], "create-success1")

		amb := TestAuthMethod(
			t, conn, databaseWrapper, org.PublicId, ActivePrivateState,
			TestConvertToUrls(t, "https://www.alice2.com")[0],
			"alice-rp", "fido2",
			WithSigningAlgs(RS256),
			WithCallbackUrls(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
		)
		ab := TestAccount(t, conn, amb.PublicId, TestConvertToUrls(t, amb.DiscoveryUrl)[0], "create-success2")

		assert.NotEqual(aa.AuthMethodId, ab.AuthMethodId)
		orig := aa.Clone()

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

func assertPublicId(t *testing.T, prefix, actual string) {
	t.Helper()
	assert.NotEmpty(t, actual)
	parts := strings.Split(actual, "_")
	assert.Equalf(t, 2, len(parts), "want one '_' in PublicId, got multiple in %q", actual)
	assert.Equalf(t, prefix, parts[0], "PublicId want prefix: %q, got: %q in %q", prefix, parts[0], actual)
}