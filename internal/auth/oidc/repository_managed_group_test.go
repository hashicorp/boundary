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
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testFakeFilter = `"/foo" == "bar"`

func TestRepository_CreateManagedGroup(t *testing.T) {
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
		t, conn, databaseWrapper, org.GetPublicId(), ActivePrivateState,
		"alice-rp", "fido",
		WithSigningAlgs(RS256),
		WithIssuer(TestConvertToUrls(t, "https://www.alice.com")[0]),
		WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)

	tests := []struct {
		name            string
		in              *ManagedGroup
		opts            []Option
		want            *ManagedGroup
		wantIsErr       errors.Code
		wantErrMsg      string
		wantErrContains string
	}{
		{
			name:       "nil-ManagedGroup",
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "oidc.(Repository).CreateManagedGroup: missing ManagedGroup: parameter violation: error #100",
		},
		{
			name:       "nil-embedded-ManagedGroup",
			in:         &ManagedGroup{},
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "oidc.(Repository).CreateManagedGroup: missing embedded ManagedGroup: parameter violation: error #100",
		},
		{
			name: "invalid-no-auth-method-id",
			in: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{},
			},
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "oidc.(Repository).CreateManagedGroup: missing auth method id: parameter violation: error #100",
		},
		{
			name: "invalid-no-filter",
			in: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					AuthMethodId: authMethod.PublicId,
				},
			},
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "oidc.(Repository).CreateManagedGroup: missing filter: parameter violation: error #100",
		},
		{
			name: "invalid-public-id-set",
			in: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					AuthMethodId: authMethod.PublicId,
					Filter:       testFakeFilter,
					PublicId:     "mgoidc_OOOOOOOOOO",
				},
			},
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "oidc.(Repository).CreateManagedGroup: public id must be empty: parameter violation: error #100",
		},
		{
			name: "valid-no-options",
			in: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					AuthMethodId: authMethod.PublicId,
					Filter:       testFakeFilter,
				},
			},
			want: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					AuthMethodId: authMethod.PublicId,
					Filter:       testFakeFilter,
				},
			},
		},
		{
			name: "valid-with-name",
			in: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					AuthMethodId: authMethod.PublicId,
					Filter:       testFakeFilter,
					Name:         "test-name-repo",
				},
			},
			want: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					AuthMethodId: authMethod.PublicId,
					Filter:       testFakeFilter,
					Name:         "test-name-repo",
				},
			},
		},
		{
			name: "valid-with-description",
			in: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					AuthMethodId: authMethod.PublicId,
					Filter:       testFakeFilter,
					Description:  ("test-description-repo"),
					Name:         "myname",
				},
			},
			want: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					AuthMethodId: authMethod.PublicId,
					Filter:       testFakeFilter,
					Description:  ("test-description-repo"),
					Name:         "myname",
				},
			},
		},
		{
			name: "duplicate-name",
			in: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					AuthMethodId: authMethod.PublicId,
					Filter:       testFakeFilter,
					Description:  ("test-description-repo"),
					Name:         "myname",
				},
			},
			wantIsErr:       errors.NotUnique,
			wantErrContains: `name "myname" already exists`,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(rw, rw, kmsCache)
			assert.NoError(err)
			require.NotNil(repo)
			got, err := repo.CreateManagedGroup(context.Background(), org.GetPublicId(), tt.in, tt.opts...)
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "Unexpected error %s", err)
				if tt.wantErrContains != "" {
					assert.True(strings.Contains(err.Error(), tt.wantErrContains))
				} else {
					assert.Equal(tt.wantErrMsg, err.Error())
				}
				return
			}
			require.NoError(err)
			assert.Empty(tt.in.PublicId)
			require.NotNil(got)
			assertPublicId(t, ManagedGroupPrefix, got.PublicId)
			assert.NotSame(tt.in, got)
			assert.Equal(tt.want.Name, got.Name)
			assert.Equal(tt.want.Description, got.Description)
			assert.Equal(got.CreateTime, got.UpdateTime)

			assert.NoError(db.TestVerifyOplog(t, rw, got.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second)))
		})
	}
}

func TestRepository_LookupManagedGroup(t *testing.T) {
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
		"alice-rp", "fido",
		WithSigningAlgs(RS256),
		WithIssuer(TestConvertToUrls(t, "https://www.alice.com")[0]),
		WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)
	mg := TestManagedGroup(t, conn, authMethod, testFakeFilter)

	newMgId, err := newManagedGroupId()
	require.NoError(t, err)
	tests := []struct {
		name       string
		in         string
		want       *ManagedGroup
		wantIsErr  errors.Code
		wantErrMsg string
	}{
		{
			name:       "With no public id",
			wantIsErr:  errors.InvalidPublicId,
			wantErrMsg: "oidc.(Repository).LookupManagedGroup: missing public id: parameter violation: error #102",
		},
		{
			name: "With non existing mg id",
			in:   newMgId,
		},
		{
			name: "With existing mg id",
			in:   mg.GetPublicId(),
			want: mg,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(rw, rw, kmsCache)
			assert.NoError(err)
			require.NotNil(repo)
			got, err := repo.LookupManagedGroup(context.Background(), tt.in)
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

func TestRepository_DeleteManagedGroup(t *testing.T) {
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
		"alice-rp", "fido",
		WithSigningAlgs(RS256),
		WithIssuer(TestConvertToUrls(t, "https://www.alice.com")[0]),
		WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)
	mg := TestManagedGroup(t, conn, authMethod, testFakeFilter)
	newMgId, err := newManagedGroupId()
	require.NoError(t, err)
	tests := []struct {
		name       string
		scopeId    string
		in         string
		want       int
		wantIsErr  errors.Code
		wantErrMsg string
	}{
		{
			name:       "With no scope id",
			scopeId:    "",
			in:         mg.GetPublicId(),
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "oidc.(Repository).DeleteManagedGroup: missing scope id: parameter violation: error #100",
		},
		{
			name:       "With no public id",
			scopeId:    org.GetPublicId(),
			wantIsErr:  errors.InvalidPublicId,
			wantErrMsg: "oidc.(Repository).DeleteManagedGroup: missing public id: parameter violation: error #102",
		},
		{
			name:    "With non existing managed group id",
			scopeId: org.GetPublicId(),
			in:      newMgId,
			want:    0,
		},
		{
			name:    "With existing managed group id",
			scopeId: org.GetPublicId(),
			in:      mg.GetPublicId(),
			want:    1,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(rw, rw, kmsCache)
			assert.NoError(err)
			require.NotNil(repo)
			got, err := repo.DeleteManagedGroup(context.Background(), tt.scopeId, tt.in)
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

func TestRepository_ListManagedGroups(t *testing.T) {
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
		"alice-rp", "fido",
		WithSigningAlgs(RS256),
		WithIssuer(TestConvertToUrls(t, "https://www.alice1.com")[0]),
		WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)
	authMethod2 := TestAuthMethod(
		t, conn, databaseWrapper, org.PublicId, ActivePrivateState,
		"alice-rp", "fido",
		WithSigningAlgs(RS256),
		WithIssuer(TestConvertToUrls(t, "https://www.alice2.com")[0]),
		WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)
	authMethod3 := TestAuthMethod(
		t, conn, databaseWrapper, org.PublicId, ActivePrivateState,
		"alice-rp", "fido",
		WithSigningAlgs(RS256),
		WithIssuer(TestConvertToUrls(t, "https://www.alice3.com")[0]),
		WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)
	mgs1 := []*ManagedGroup{
		TestManagedGroup(t, conn, authMethod1, testFakeFilter),
		TestManagedGroup(t, conn, authMethod1, testFakeFilter),
		TestManagedGroup(t, conn, authMethod1, testFakeFilter),
	}
	sort.Slice(mgs1, func(i, j int) bool {
		return strings.Compare(mgs1[i].PublicId, mgs1[j].PublicId) < 0
	})

	mgs2 := []*ManagedGroup{
		TestManagedGroup(t, conn, authMethod2, testFakeFilter),
		TestManagedGroup(t, conn, authMethod2, testFakeFilter),
		TestManagedGroup(t, conn, authMethod2, testFakeFilter),
	}
	sort.Slice(mgs2, func(i, j int) bool {
		return strings.Compare(mgs2[i].PublicId, mgs2[j].PublicId) < 0
	})

	tests := []struct {
		name       string
		in         string
		opts       []Option
		want       []*ManagedGroup
		wantIsErr  errors.Code
		wantErrMsg string
	}{
		{
			name:       "With no auth method id",
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "oidc.(Repository).ListManagedGroups: missing auth method id: parameter violation: error #100",
		},
		{
			name: "With no managed groups",
			in:   authMethod3.GetPublicId(),
			want: []*ManagedGroup{},
		},
		{
			name: "With first auth method id",
			in:   authMethod1.GetPublicId(),
			want: mgs1,
		},
		{
			name: "With first auth method id",
			in:   authMethod2.GetPublicId(),
			want: mgs2,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(rw, rw, kmsCache)
			assert.NoError(err)
			require.NotNil(repo)
			got, err := repo.ListManagedGroups(context.Background(), tt.in, tt.opts...)
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "Unexpected error %s", err)
				assert.Equal(tt.wantErrMsg, err.Error())
				return
			}
			require.NoError(err)

			sort.Slice(got, func(i, j int) bool {
				return strings.Compare(got[i].PublicId, got[j].PublicId) < 0
			})

			assert.EqualValues(tt.want, got)
		})
	}
}

func TestRepository_ListManagedGroups_Limits(t *testing.T) {
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
		"alice-rp", "fido",
		WithSigningAlgs(RS256),
		WithIssuer(TestConvertToUrls(t, "https://www.alice1.com")[0]),
		WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)

	mgCount := 10
	for i := 0; i < mgCount; i++ {
		TestManagedGroup(t, conn, am, fmt.Sprintf(`"/foo/%d" == "bar"`, i))
	}

	tests := []struct {
		name     string
		repoOpts []Option
		listOpts []Option
		wantLen  int
	}{
		{
			name:    "With no limits",
			wantLen: mgCount,
		},
		{
			name:     "With repo limit",
			repoOpts: []Option{WithLimit(3)},
			wantLen:  3,
		},
		{
			name:     "With negative repo limit",
			repoOpts: []Option{WithLimit(-1)},
			wantLen:  mgCount,
		},
		{
			name:     "With List limit",
			listOpts: []Option{WithLimit(3)},
			wantLen:  3,
		},
		{
			name:     "With negative List limit",
			listOpts: []Option{WithLimit(-1)},
			wantLen:  mgCount,
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
			got, err := repo.ListManagedGroups(context.Background(), am.GetPublicId(), tt.listOpts...)
			require.NoError(err)
			assert.Len(got, tt.wantLen)
		})
	}
}

/*
func TestRepository_UpdateAccount(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iamRepo)

	databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	am := TestAuthMethod(
		t, conn, databaseWrapper, org.PublicId, ActivePrivateState,
		"alice-rp", "fido",
		WithSigningAlgs(RS256),
		WithIssuer(TestConvertToUrls(t, "https://www.alice.com")[0]),
		WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)

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
		scopeId    string
		version    uint32
		orig       *Account
		chgFn      func(*Account) *Account
		masks      []string
		want       *Account
		wantCount  int
		wantIsErr  errors.Code
		wantErrMsg string
	}{
		{
			name:    "nil-Account",
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &Account{
				Account: &store.Account{},
			},
			chgFn:      makeNil(),
			masks:      []string{NameField, DescriptionField},
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "oidc.(Repository).UpdateAccount: missing Account: parameter violation: error #100",
		},
		{
			name:    "nil-embedded-Account",
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &Account{
				Account: &store.Account{},
			},
			chgFn:      makeEmbeddedNil(),
			masks:      []string{NameField, DescriptionField},
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "oidc.(Repository).UpdateAccount: missing embedded Account: parameter violation: error #100",
		},
		{
			name:    "no-scope-id",
			version: 1,
			orig: &Account{
				Account: &store.Account{
					Name: "no-scope-id-test-name-repo",
				},
			},
			chgFn:      changeName("no-scope-id-test-update-name-repo"),
			masks:      []string{NameField},
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "oidc.(Repository).UpdateAccount: missing scope id: parameter violation: error #100",
		},
		{
			name:    "missing-version",
			scopeId: org.GetPublicId(),
			orig: &Account{
				Account: &store.Account{
					Name: "missing-version-test-name-repo",
				},
			},
			chgFn:      changeName("test-update-name-repo"),
			masks:      []string{NameField},
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "oidc.(Repository).UpdateAccount: missing version: parameter violation: error #100",
		},
		{
			name:    "no-public-id",
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &Account{
				Account: &store.Account{},
			},
			chgFn:      deletePublicId(),
			masks:      []string{NameField, DescriptionField},
			wantIsErr:  errors.InvalidPublicId,
			wantErrMsg: "oidc.(Repository).UpdateAccount: missing public id: parameter violation: error #102",
		},
		{
			name:    "updating-non-existent-Account",
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &Account{
				Account: &store.Account{
					Name: "updating-non-existent-Account-test-name-repo",
				},
			},
			chgFn:      combine(nonExistentPublicId(), changeName("updating-non-existent-Account-test-update-name-repo")),
			masks:      []string{NameField},
			wantIsErr:  errors.RecordNotFound,
			wantErrMsg: "oidc.(Repository).UpdateAccount: abcd_OOOOOOOOOO: db.DoTx: oidc.(Repository).UpdateAccount: db.Update: db.lookupAfterWrite: db.LookupById: record not found, search issue: error #1100",
		},
		{
			name:    "empty-field-mask",
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &Account{
				Account: &store.Account{
					Name: "empty-field-mask-test-name-repo",
				},
			},
			chgFn:      changeName("empty-field-mask-test-update-name-repo"),
			wantIsErr:  errors.EmptyFieldMask,
			wantErrMsg: "oidc.(Repository).UpdateAccount: missing field mask: parameter violation: error #104",
		},
		{
			name:    "read-only-fields-in-field-mask",
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &Account{
				Account: &store.Account{
					Name: "read-only-fields-in-field-mask-test-name-repo",
				},
			},
			chgFn:      changeName("read-only-fields-in-field-mask-test-update-name-repo"),
			masks:      []string{"PublicId", "CreateTime", "UpdateTime", "AuthMethodId"},
			wantIsErr:  errors.InvalidFieldMask,
			wantErrMsg: "oidc.(Repository).UpdateAccount: PublicId: parameter violation: error #103",
		},
		{
			name:    "unknown-field-in-field-mask",
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &Account{
				Account: &store.Account{
					Name: "unknown-field-in-field-mask-test-name-repo",
				},
			},
			chgFn:      changeName("unknown-field-in-field-mask-test-update-name-repo"),
			masks:      []string{"Bilbo"},
			wantIsErr:  errors.InvalidFieldMask,
			wantErrMsg: "oidc.(Repository).UpdateAccount: Bilbo: parameter violation: error #103",
		},
		{
			name:    "change-name",
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &Account{
				Account: &store.Account{
					Name: "change-name-test-name-repo",
				},
			},
			chgFn: changeName("change-name-test-update-name-repo"),
			masks: []string{NameField},
			want: &Account{
				Account: &store.Account{
					Name: "change-name-test-update-name-repo",
				},
			},
			wantCount: 1,
		},
		{
			name:    "change-description",
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &Account{
				Account: &store.Account{
					Description: "test-description-repo",
				},
			},
			chgFn: changeDescription("test-update-description-repo"),
			masks: []string{DescriptionField},
			want: &Account{
				Account: &store.Account{
					Description: "test-update-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name:    "change-name-and-description",
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &Account{
				Account: &store.Account{
					Name:        "change-name-and-description-test-name-repo",
					Description: "test-description-repo",
				},
			},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("change-name-and-description-test-update-name-repo")),
			masks: []string{NameField, DescriptionField},
			want: &Account{
				Account: &store.Account{
					Name:        "change-name-and-description-test-update-name-repo",
					Description: "test-update-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name:    "delete-name",
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &Account{
				Account: &store.Account{
					Name:        "delete-name-test-name-repo",
					Description: "test-description-repo",
				},
			},
			masks: []string{NameField},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("")),
			want: &Account{
				Account: &store.Account{
					Description: "test-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name:    "delete-description",
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &Account{
				Account: &store.Account{
					Name:        "delete-description-test-name-repo",
					Description: "test-description-repo",
				},
			},
			masks: []string{DescriptionField},
			chgFn: combine(changeDescription(""), changeName("test-update-name-repo")),
			want: &Account{
				Account: &store.Account{
					Name: "delete-description-test-name-repo",
				},
			},
			wantCount: 1,
		},
		{
			name:    "do-not-delete-name",
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &Account{
				Account: &store.Account{
					Name:        "do-not-delete-name-test-name-repo",
					Description: "test-description-repo",
				},
			},
			masks: []string{DescriptionField},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("")),
			want: &Account{
				Account: &store.Account{
					Name:        "do-not-delete-name-test-name-repo",
					Description: "test-update-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name:    "do-not-delete-description",
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &Account{
				Account: &store.Account{
					Name:        "do-not-delete-description-test-name-repo",
					Description: "test-description-repo",
				},
			},
			masks: []string{NameField},
			chgFn: combine(changeDescription(""), changeName("do-not-delete-description-test-update-name-repo")),
			want: &Account{
				Account: &store.Account{
					Name:        "do-not-delete-description-test-update-name-repo",
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

			orig := TestAccount(t, conn, am, tt.name, WithName(tt.orig.GetName()), WithDescription(tt.orig.GetDescription()))

			tt.orig.AuthMethodId = am.PublicId
			if tt.chgFn != nil {
				orig = tt.chgFn(orig)
			}
			got, gotCount, err := repo.UpdateAccount(context.Background(), tt.scopeId, orig, tt.version, tt.masks)
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
			"alice-rp", "fido",
			WithSigningAlgs(RS256),
			WithIssuer(TestConvertToUrls(t, "https://www.alice.com")[0]),
			WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
		)
		aa := TestAccount(t, conn, am, "create-success1")
		ab := TestAccount(t, conn, am, "create-success2")

		aa.Name = name
		got1, gotCount1, err := repo.UpdateAccount(context.Background(), org.GetPublicId(), aa, 1, []string{NameField})
		assert.NoError(err)
		require.NotNil(got1)
		assert.Equal(name, got1.Name)
		assert.Equal(1, gotCount1, "row count")
		assert.NoError(db.TestVerifyOplog(t, rw, aa.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))

		ab.Name = name
		got2, gotCount2, err := repo.UpdateAccount(context.Background(), org.GetPublicId(), ab, 1, []string{NameField})
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
			"alice-rp", "fido",
			WithSigningAlgs(RS256),
			WithIssuer(TestConvertToUrls(t, "https://www.alice.com")[0]),
			WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
		)
		aa := TestAccount(t, conn, ama, "create-success1", WithName("test-name-aa"))

		amb := TestAuthMethod(
			t, conn, databaseWrapper, org.PublicId, ActivePrivateState,
			"alice-rp", "fido2",
			WithSigningAlgs(RS256),
			WithIssuer(TestConvertToUrls(t, "https://www.alice2.com")[0]),
			WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
		)
		ab := TestAccount(t, conn, amb, "create-success2", WithName("test-name-ab"))

		ab.Name = aa.Name
		got3, gotCount3, err := repo.UpdateAccount(context.Background(), org.GetPublicId(), ab, 1, []string{NameField})
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
			"alice-rp", "fido",
			WithSigningAlgs(RS256),
			WithIssuer(TestConvertToUrls(t, "https://www.alice.com")[0]),
			WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
		)
		aa := TestAccount(t, conn, ama, "create-success1")

		amb := TestAuthMethod(
			t, conn, databaseWrapper, org.PublicId, ActivePrivateState,
			"alice-rp", "fido2",
			WithSigningAlgs(RS256),
			WithIssuer(TestConvertToUrls(t, "https://www.alice2.com")[0]),
			WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
		)
		ab := TestAccount(t, conn, amb, "create-success2")

		assert.NotEqual(aa.AuthMethodId, ab.AuthMethodId)
		orig := aa.Clone()

		aa.AuthMethodId = ab.AuthMethodId
		assert.Equal(aa.AuthMethodId, ab.AuthMethodId)

		got1, gotCount1, err := repo.UpdateAccount(context.Background(), org.GetPublicId(), aa, 1, []string{NameField})

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
*/
