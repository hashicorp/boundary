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
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	}()

	_, prj := iam.TestScopes(t, conn)

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
			name: "blank-scopeId",
			args: args{
				scopeId: "",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "valid-no-options",
			args: args{
				scopeId: prj.GetPublicId(),
			},
			want: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					ScopeId: prj.GetPublicId(),
				},
			},
		},
		{
			name: "valid-with-name",
			args: args{
				scopeId: prj.GetPublicId(),
				opts: []Option{
					WithName("test-name"),
				},
			},
			want: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					ScopeId: prj.GetPublicId(),
					Name:    "test-name",
				},
			},
		},
		{
			name: "valid-with-description",
			args: args{
				scopeId: prj.GetPublicId(),
				opts: []Option{
					WithDescription("test-description"),
				},
			},
			want: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					ScopeId:     prj.GetPublicId(),
					Description: "test-description",
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewAuthMethod(tt.args.scopeId, tt.args.opts...)
			if tt.wantErr {
				assert.Error(err)
				require.Nil(got)
				return
			}
			assert.NoError(err)
			require.NotNil(got)

			assert.Emptyf(got.PublicId, "PublicId set")
			assert.Equal(tt.want, got)

			id, err := newAuthMethodId()
			assert.NoError(err)

			tt.want.PublicId = id
			got.PublicId = id

			w := db.New(conn)
			err2 := w.Create(context.Background(), got)
			assert.NoError(err2)
		})
	}
}
