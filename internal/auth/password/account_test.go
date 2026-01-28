// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

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

func TestAccount_New(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	o, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	auts := TestAuthMethods(t, conn, o.GetPublicId(), 1)
	aut := auts[0]

	type args struct {
		authMethodId string
		opts         []Option
	}

	tests := []struct {
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
			},
			want: &Account{
				Account: &store.Account{
					AuthMethodId: aut.GetPublicId(),
				},
			},
		},
		{
			name: "valid-with-user-name",
			args: args{
				authMethodId: aut.GetPublicId(),
				opts: []Option{
					WithLoginName("kazmierczak1"),
				},
			},
			want: &Account{
				Account: &store.Account{
					AuthMethodId: aut.GetPublicId(),
					LoginName:    "kazmierczak1",
				},
			},
		},
		{
			name: "valid-with-name",
			args: args{
				authMethodId: aut.GetPublicId(),
				opts: []Option{
					WithName("test-name"),
				},
			},
			want: &Account{
				Account: &store.Account{
					AuthMethodId: aut.GetPublicId(),
					Name:         "test-name",
				},
			},
		},
		{
			name: "valid-with-description",
			args: args{
				authMethodId: aut.GetPublicId(),
				opts: []Option{
					WithDescription("test-description"),
				},
			},
			want: &Account{
				Account: &store.Account{
					AuthMethodId: aut.GetPublicId(),
					Description:  "test-description",
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewAccount(context.Background(), tt.args.authMethodId, tt.args.opts...)
			if tt.wantErr {
				assert.Error(err)
				require.Nil(got)
				return
			}
			assert.NoError(err)
			require.NotNil(got)

			assert.Emptyf(got.PublicId, "PublicId set")
			assert.Equal(tt.want, got)
		})
	}
}
