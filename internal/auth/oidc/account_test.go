package oidc

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestAccount_Create(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	rw := db.New(conn)

	databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	testAuthMethod := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, TestConvertToUrls(t, "https://alice.com")[0], "alice_rp", "my-dogs-name")

	type args struct {
		authMethodId string
		issuerId     *url.URL
		subjectId    string
		opts         []Option
	}
	tests := []struct {
		name            string
		args            args
		want            *Account
		wantErr         bool
		wantIsErr       errors.Code
		create          bool
		wantCreateErr   bool
		wantCreateIsErr errors.Code
	}{
		{
			name: "valid",
			args: args{
				authMethodId: testAuthMethod.PublicId,
				issuerId:     TestConvertToUrls(t, "https://alice.com")[0],
				subjectId:    "alice",
				opts:         []Option{WithEmail("alice@alice.com"), WithFullName("Alice Eve Smith"), WithName("alice's restuarant"), WithDescription("A good place to eat")},
			},
			create: true,
			want: func() *Account {
				want, err := NewAccount(testAuthMethod.PublicId, TestConvertToUrls(t, "https://alice.com")[0], "alice", WithEmail("alice@alice.com"), WithFullName("Alice Eve Smith"), WithName("alice's restuarant"), WithDescription("A good place to eat"))
				require.NoError(t, err)
				return want
			}(),
		},
		{
			name: "dup", // must follow "valid" test.
			args: args{
				authMethodId: testAuthMethod.PublicId,
				issuerId:     TestConvertToUrls(t, "https://alice.com")[0],
				subjectId:    "alice",
				opts:         []Option{WithEmail("alice@alice.com"), WithFullName("Alice Eve Smith"), WithName("alice's restuarant"), WithDescription("A good place to eat")},
			},
			create: true,
			want: func() *Account {
				want, err := NewAccount(testAuthMethod.PublicId, TestConvertToUrls(t, "https://alice.com")[0], "alice", WithEmail("alice@alice.com"), WithFullName("Alice Eve Smith"), WithName("alice's restuarant"), WithDescription("A good place to eat"))
				require.NoError(t, err)
				return want
			}(),
			wantCreateErr:   true,
			wantCreateIsErr: errors.NotUnique,
		},
		{
			name: "empty-auth-method",
			args: args{
				authMethodId: "",
				issuerId:     TestConvertToUrls(t, "https://alice.com")[0],
				subjectId:    "alice",
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "empty-issuer",
			args: args{
				authMethodId: testAuthMethod.PublicId,
				issuerId:     nil,
				subjectId:    "alice",
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "empty-subject",
			args: args{
				authMethodId: testAuthMethod.PublicId,
				issuerId:     TestConvertToUrls(t, "https://alice.com")[0],
				subjectId:    "",
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "email-too-long",
			args: args{
				authMethodId: testAuthMethod.PublicId,
				issuerId:     TestConvertToUrls(t, "https://alice.com")[0],
				subjectId:    "alice",
				opts:         []Option{WithEmail(strings.Repeat("a", 500) + "@alice.com")},
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "name-too-long",
			args: args{
				authMethodId: testAuthMethod.PublicId,
				issuerId:     TestConvertToUrls(t, "https://alice.com")[0],
				subjectId:    "alice",
				opts:         []Option{WithFullName(strings.Repeat("a", 750))},
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "empty-issuer-url",
			args: args{
				authMethodId: testAuthMethod.PublicId,
				issuerId:     &url.URL{},
				subjectId:    "alice",
				opts:         []Option{WithFullName(strings.Repeat("a", 750))},
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewAccount(tt.args.authMethodId, tt.args.issuerId, tt.args.subjectId, tt.args.opts...)
			if tt.wantErr {
				require.Error(err)
				assert.True(errors.Match(errors.T(tt.wantIsErr), err))
				return
			}
			require.NoError(err)
			assert.Equal(tt.want, got)
			if tt.create {
				ctx := context.Background()
				id, err := newAccountId(testAuthMethod.GetPublicId(), tt.args.issuerId.String(), tt.args.subjectId)
				require.NoError(err)
				got.PublicId = id
				err = rw.Create(ctx, got)
				if tt.wantCreateErr {
					assert.Error(err)
					assert.True(errors.Match(errors.T(tt.wantCreateIsErr), err))
					return
				} else {
					assert.NoError(err)
				}
				found := AllocAccount()
				found.PublicId = id
				err = rw.LookupByPublicId(ctx, found)
				require.NoError(err)
				assert.Equal(got, found)
			}
		})
	}
}

func TestAccount_Delete(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	rw := db.New(conn)

	databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	testAuthMethod :=
		TestAuthMethod(
			t,
			conn,
			databaseWrapper,
			org.PublicId,
			InactiveState,
			TestConvertToUrls(t, "https://alice.com")[0],
			"alice_rp",
			"my-dogs-name")

	testResource := func(authMethodId string, issuer, subject string) *Account {
		i, err := url.Parse(issuer)
		require.NoError(t, err)
		a, err := NewAccount(authMethodId, i, subject)
		require.NoError(t, err)
		id, err := newAccountId(testAuthMethod.GetPublicId(), issuer, subject)
		require.NoError(t, err)
		a.PublicId = id
		return a
	}

	// seed an extra callback url to just make sure the delete only gets the right num of rows
	seedAccount := testResource(testAuthMethod.PublicId, "http://alice.com", "jane")
	require.NoError(t, rw.Create(context.Background(), &seedAccount))

	tests := []struct {
		name            string
		Account         *Account
		wantRowsDeleted int
		overrides       func(*Account)
		wantErr         bool
		wantErrMsg      string
	}{
		{
			name:            "valid",
			Account:         testResource(testAuthMethod.PublicId, "https://alice.com", "alice"),
			wantErr:         false,
			wantRowsDeleted: 1,
		},
		{
			name:            "bad-publicId",
			Account:         testResource(testAuthMethod.PublicId, "https://alice.com", "bad-publicId"),
			overrides:       func(c *Account) { c.PublicId = "bad-id" },
			wantErr:         false,
			wantRowsDeleted: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			ctx := context.Background()
			cp := tt.Account.Clone()
			require.NoError(rw.Create(ctx, &cp))

			if tt.overrides != nil {
				tt.overrides(cp)
			}
			deletedRows, err := rw.Delete(ctx, &cp)
			if tt.wantErr {
				require.Error(err)
				return
			}
			require.NoError(err)
			if tt.wantRowsDeleted == 0 {
				assert.Equal(tt.wantRowsDeleted, deletedRows)
				return
			}
			assert.Equal(tt.wantRowsDeleted, deletedRows)
			found := AllocAccount()
			found.PublicId = tt.Account.PublicId
			err = rw.LookupByPublicId(ctx, found)
			assert.True(errors.IsNotFoundError(err))
		})
	}
}

func TestAccount_Clone(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)

	t.Run("valid", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
		require.NoError(err)
		m := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, TestConvertToUrls(t, "https://alice.com")[0], "alice_rp", "my-dogs-name")
		orig, err := NewAccount(m.PublicId, TestConvertToUrls(t, "https://alice.com")[0], "alice", WithFullName("Alice Eve Smith"), WithEmail("alice@alice.com"))
		require.NoError(err)
		cp := orig.Clone()
		assert.True(proto.Equal(cp.Account, orig.Account))
	})
	t.Run("not-equal", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
		require.NoError(err)
		m := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, TestConvertToUrls(t, "https://alice.com")[0], "alice_rp", "my-dogs-name")
		orig, err := NewAccount(m.PublicId, TestConvertToUrls(t, "https://alice.com")[0], "alice", WithFullName("Alice Eve Smith"), WithEmail("alice@alice.com"))
		require.NoError(err)
		orig2, err := NewAccount(m.PublicId, TestConvertToUrls(t, "https://alice.com")[0], "bob", WithFullName("Bob Eve Smith"), WithEmail("bob@alice.com"))
		require.NoError(err)

		cp := orig.Clone()
		assert.True(!proto.Equal(cp.Account, orig2.Account))
	})
}

func TestAccount_SetTableName(t *testing.T) {
	t.Parallel()
	defaultTableName := defaultAccountTableName
	tests := []struct {
		name      string
		setNameTo string
		want      string
	}{
		{
			name:      "new-name",
			setNameTo: "new-name",
			want:      "new-name",
		},
		{
			name:      "reset to default",
			setNameTo: "",
			want:      defaultTableName,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			def := AllocAccount()
			require.Equal(defaultTableName, def.TableName())
			m := AllocAccount()
			m.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, m.TableName())
		})
	}
}
