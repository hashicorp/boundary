package password

import (
	"context"
	"testing"

	"github.com/hashicorp/watchtower/internal/auth/password/store"
	"github.com/hashicorp/watchtower/internal/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccount_New(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")

	w := db.New(conn)
	auts := testAuthMethods(t, conn, 1)
	aut := auts[0]

	type args struct {
		authMethodId string
		userName     string
		opts         []Option
	}

	var tests = []struct {
		name    string
		args    args
		want    *Account
		wantErr bool
	}{
		{
			name: "blank-authMethodId",
			args: args{
				authMethodId: "",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "valid-no-options",
			args: args{
				authMethodId: aut.GetPublicId(),
				userName:     "kazmierczak",
			},
			want: &Account{
				Account: &store.Account{
					AuthMethodId: aut.GetPublicId(),
					UserName:     "kazmierczak",
				},
			},
		},
		{
			name: "valid-with-name",
			args: args{
				authMethodId: aut.GetPublicId(),
				userName:     "kazmierczak1",
				opts: []Option{
					WithName("test-name"),
				},
			},
			want: &Account{
				Account: &store.Account{
					AuthMethodId: aut.GetPublicId(),
					UserName:     "kazmierczak1",
					Name:         "test-name",
				},
			},
		},
		{
			name: "valid-with-description",
			args: args{
				authMethodId: aut.GetPublicId(),
				userName:     "kazmierczak2",
				opts: []Option{
					WithDescription("test-description"),
				},
			},
			want: &Account{
				Account: &store.Account{
					AuthMethodId: aut.GetPublicId(),
					UserName:     "kazmierczak2",
					Description:  "test-description",
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewAccount(tt.args.authMethodId, tt.args.userName, tt.args.opts...)
			if tt.wantErr {
				assert.Error(err)
				require.Nil(got)
				return
			}
			assert.NoError(err)
			require.NotNil(got)

			assert.Emptyf(got.PublicId, "PublicId set")
			assert.Equal(tt.want, got)

			id, err := newAccountId()
			assert.NoError(err)

			tt.want.PublicId = id
			got.PublicId = id

			err2 := w.Create(context.Background(), got)
			assert.NoError(err2)
		})
	}
}
