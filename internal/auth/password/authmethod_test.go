package password

import (
	"context"
	"testing"

	"github.com/hashicorp/watchtower/internal/auth/password/store"
	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/iam"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testAuthMethods(t *testing.T, conn *gorm.DB, count int) []*AuthMethod {
	t.Helper()
	assert, require := assert.New(t), require.New(t)
	w := db.New(conn)
	org, _ := iam.TestScopes(t, conn)
	var auts []*AuthMethod
	for i := 0; i < count; i++ {
		cat, err := NewAuthMethod(org.GetPublicId())
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
		auts = append(auts, cat)
	}
	return auts
}

func TestAuthMethod_New(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")

	w := db.New(conn)

	type args struct {
		scopeId string
		opts    []Option
	}

	var tests = []struct {
		name    string
		args    args
		want    *AuthMethod
		wantErr bool
	}{
		{
			name: "valid-no-options",
			args: args{},
			want: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					MinUserNameLength: 5,
					MinPasswordLength: 8,
				},
			},
		},
		{
			name: "valid-with-name",
			args: args{
				opts: []Option{
					WithName("test-name"),
				},
			},
			want: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					Name:              "test-name",
					MinUserNameLength: 5,
					MinPasswordLength: 8,
				},
			},
		},
		{
			name: "valid-with-description",
			args: args{
				opts: []Option{
					WithDescription("test-description"),
				},
			},
			want: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					Description:       "test-description",
					MinUserNameLength: 5,
					MinPasswordLength: 8,
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			org, _ := iam.TestScopes(t, conn)
			got, err := NewAuthMethod(org.GetPublicId(), tt.args.opts...)
			if tt.wantErr {
				assert.Error(err)
				require.Nil(got)
				return
			}
			require.NoError(err)
			require.NotNil(got)

			tt.want.ScopeId = org.GetPublicId()

			assert.Emptyf(got.PublicId, "PublicId set")
			assert.Equal(tt.want, got)

			id, err := newAuthMethodId()
			assert.NoError(err)

			tt.want.PublicId = id
			got.PublicId = id

			conn.LogMode(true)
			ctx := context.Background()
			_, err2 := w.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
				func(_ db.Reader, iw db.Writer) error {
					return iw.Create(ctx, got)
				},
			)
			conn.LogMode(false)
			assert.NoError(err2)
		})
	}

	t.Run("blank-scopeId", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		got, err := NewAuthMethod("")
		assert.Error(err)
		require.Nil(got)
	})
}
