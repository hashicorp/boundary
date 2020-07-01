package password

import (
	"context"
	"testing"

	"github.com/hashicorp/watchtower/internal/auth/password/store"
	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthMethod_New(t *testing.T) {
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	t.Cleanup(func() {
		err := cleanup()
		assert.NoError(t, err)
		err = conn.Close()
		assert.NoError(t, err)
	})

	// conn.LogMode(true)
	w := db.New(conn)

	/*
		- minUserNameLength default is 5
		- minPasswordLength is 8
		- duplicate name in scope

		insert new method, verify argon2 conf with default parameters created
		update authMethod with new conf
		verify new conf
		update authMethod with old conf params
		verify old config set
	*/

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
			_, prj := iam.TestScopes(t, conn)
			got, err := NewAuthMethod(prj.GetPublicId(), tt.args.opts...)
			if tt.wantErr {
				assert.Error(err)
				require.Nil(got)
				return
			}
			require.NoError(err)
			require.NotNil(got)

			tt.want.ScopeId = prj.GetPublicId()

			assert.Emptyf(got.PublicId, "PublicId set")
			assert.Equal(tt.want, got)

			id, err := newAuthMethodId()
			assert.NoError(err)

			tt.want.PublicId = id
			got.PublicId = id

			conf, err := NewArgon2Configuration(id)
			require.NoError(err)
			require.NotNil(conf)

			got.PasswordConfId = conf.PublicId

			ctx := context.Background()
			_, err2 := w.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
				func(_ db.Reader, iw db.Writer) error {
					if err := iw.Create(ctx, conf); err != nil {
						t.Log(err)
						return err
					}
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
