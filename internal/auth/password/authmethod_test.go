package password

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/auth/password/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthMethod_New(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)

	w := db.New(conn)

	type args struct {
		opts []Option
	}

	tests := []struct {
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
					MinLoginNameLength: 3,
					MinPasswordLength:  8,
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
					Name:               "test-name",
					MinLoginNameLength: 3,
					MinPasswordLength:  8,
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
					Description:        "test-description",
					MinLoginNameLength: 3,
					MinPasswordLength:  8,
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
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

			conf := NewArgon2Configuration()
			require.NotNil(conf)
			conf.PrivateId, err = newArgon2ConfigurationId()
			require.NoError(err)
			conf.PasswordMethodId = got.PublicId
			got.PasswordConfId = conf.PrivateId

			ctx := context.Background()
			_, err2 := w.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
				func(_ db.Reader, iw db.Writer) error {
					require.NoError(iw.Create(ctx, conf))
					return iw.Create(ctx, got)
				},
			)
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
