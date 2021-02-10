package oidc

import (
	"context"
	"net/url"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestCallbackUrl_Create(t *testing.T) {
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
		callback     *url.URL
	}
	tests := []struct {
		name            string
		args            args
		want            *CallbackUrl
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
				callback:     TestConvertToUrls(t, "https://alice.com")[0],
			},
			create: true,
			want: func() *CallbackUrl {
				want := AllocCallbackUrl()
				want.OidcMethodId = testAuthMethod.PublicId
				want.Url = "https://alice.com"
				return &want
			}(),
		},
		{
			name: "dup", // must follow "valid" test. Url must be be unique for an OidcMethodId
			args: args{
				authMethodId: testAuthMethod.PublicId,
				callback:     TestConvertToUrls(t, "https://alice.com")[0],
			},
			create: true,
			want: func() *CallbackUrl {
				want := AllocCallbackUrl()
				want.OidcMethodId = testAuthMethod.PublicId
				want.Url = "https://alice.com"
				return &want
			}(),
			wantCreateErr:   true,
			wantCreateIsErr: errors.NotUnique,
		},
		{
			name: "empty-auth-method",
			args: args{
				authMethodId: "",
				callback:     TestConvertToUrls(t, "https://alice.com")[0],
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "nil-url",
			args: args{
				authMethodId: testAuthMethod.PublicId,
				callback:     nil,
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewCallbackUrl(tt.args.authMethodId, tt.args.callback)
			if tt.wantErr {
				require.Error(err)
				assert.True(errors.Match(errors.T(tt.wantIsErr), err))
				return
			}
			require.NoError(err)
			assert.Equal(tt.want, got)
			if tt.create {
				ctx := context.Background()
				err = rw.Create(ctx, got)
				if tt.wantCreateErr {
					assert.Error(err)
					assert.True(errors.Match(errors.T(tt.wantCreateIsErr), err))
					return
				} else {
					assert.NoError(err)
				}
				found := AllocCallbackUrl()
				require.NoError(rw.LookupWhere(ctx, &found, "oidc_method_id = ? and callback_url = ?", tt.args.authMethodId, tt.args.callback.String()))
				assert.Equal(got, &found)
			}
		})
	}
}

func TestCallbackUrl_Delete(t *testing.T) {
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
			"my-dogs-name",
			WithCallbackUrls(TestConvertToUrls(t, "http://unique.com/callback")...)) // seed an extra callback url to just make sure the delete only gets the right num of rows

	testResource := func(authMethodId string, callbackUrl string) *CallbackUrl {
		c, err := NewCallbackUrl(authMethodId, TestConvertToUrls(t, callbackUrl)[0])
		require.NoError(t, err)
		return c
	}
	tests := []struct {
		name            string
		callbackUrl     *CallbackUrl
		wantRowsDeleted int
		overrides       func(*CallbackUrl)
		wantErr         bool
		wantErrMsg      string
	}{
		{
			name:            "valid",
			callbackUrl:     testResource(testAuthMethod.PublicId, "https://alice.com/callback"),
			wantErr:         false,
			wantRowsDeleted: 1,
		},
		{
			name:            "bad-OidcMethodId",
			callbackUrl:     testResource(testAuthMethod.PublicId, "https://bad-id/callback"),
			overrides:       func(c *CallbackUrl) { c.OidcMethodId = "bad-id" },
			wantErr:         false,
			wantRowsDeleted: 0,
		},
		{
			name:            "bad-Url",
			callbackUrl:     testResource(testAuthMethod.PublicId, "https://bad-url.com/callback"),
			overrides:       func(c *CallbackUrl) { c.Url = "https://bad-url" },
			wantErr:         false,
			wantRowsDeleted: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			ctx := context.Background()
			cp := tt.callbackUrl.Clone()
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
			found := AllocCallbackUrl()
			err = rw.LookupWhere(ctx, &found, "oidc_method_id = ? and callback_url = ?", tt.callbackUrl.OidcMethodId, tt.callbackUrl.Url)
			assert.True(errors.IsNotFoundError(err))
		})
	}
}

func TestCallbackUrl_Clone(t *testing.T) {
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
		orig, err := NewCallbackUrl(m.PublicId, TestConvertToUrls(t, "https://alice.com/callback")[0])
		require.NoError(err)
		cp := orig.Clone()
		assert.True(proto.Equal(cp.CallbackUrl, orig.CallbackUrl))
	})
	t.Run("not-equal", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
		require.NoError(err)
		m := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, TestConvertToUrls(t, "https://alice.com")[0], "alice_rp", "my-dogs-name")
		orig, err := NewCallbackUrl(m.PublicId, TestConvertToUrls(t, "https://alice.com/callback")[0])
		require.NoError(err)
		orig2, err := NewCallbackUrl(m.PublicId, TestConvertToUrls(t, "https://bob.com/callback")[0])
		require.NoError(err)

		cp := orig.Clone()
		assert.True(!proto.Equal(cp.CallbackUrl, orig2.CallbackUrl))
	})
}

func TestCallbackUrl_SetTableName(t *testing.T) {
	t.Parallel()
	defaultTableName := defaultCallbackUrlTableName
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
			def := AllocCallbackUrl()
			require.Equal(defaultTableName, def.TableName())
			m := AllocCallbackUrl()
			m.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, m.TableName())
		})
	}
}
