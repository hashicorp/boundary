// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ldap

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/auth/ldap/store"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestNewDerefAliases(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	tests := []struct {
		name            string
		ctx             context.Context
		authMethodId    string
		derefAliases    DerefAliasType
		want            *DerefAliases
		wantErr         bool
		wantErrCode     errors.Code
		wantErrContains string
	}{
		{
			name:         "valid-DerefAlways",
			ctx:          testCtx,
			authMethodId: "test-id",
			derefAliases: DerefAlways,
			want: &DerefAliases{
				DerefAliases: &store.DerefAliases{
					LdapMethodId:       "test-id",
					DereferenceAliases: string(DerefAlways),
				},
			},
		},
		{
			name:            "missing-auth-method-id",
			ctx:             testCtx,
			derefAliases:    DerefAlways,
			wantErr:         true,
			wantErrCode:     errors.InvalidParameter,
			wantErrContains: "missing auth method id",
		},
		{
			name:            "missing-deref-aliases",
			ctx:             testCtx,
			authMethodId:    "test-id",
			wantErr:         true,
			wantErrCode:     errors.InvalidParameter,
			wantErrContains: "missing dereference alias type",
		},
		{
			name:            "invalid-deref-aliases",
			ctx:             testCtx,
			authMethodId:    "test-id",
			derefAliases:    "invalid",
			wantErr:         true,
			wantErrCode:     errors.InvalidParameter,
			wantErrContains: `"invalid" is not a valid ldap dereference alias type`,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewDerefAliases(tc.ctx, tc.authMethodId, tc.derefAliases)
			if tc.wantErr {
				require.Error(err)
				assert.Nil(got)
				if tc.wantErrCode != errors.Unknown {
					assert.True(errors.Match(errors.T(tc.wantErrCode), err))
				}
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			assert.Equal(tc.want, got)
		})
	}
}

func TestDerefAliases_SetTableName(t *testing.T) {
	t.Parallel()
	defaultTableName := derefAliasesTableName
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
			deref := allocDerefAliases()
			require.Equal(defaultTableName, deref.TableName())
			derefOverriddenTableName := allocDerefAliases()
			derefOverriddenTableName.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, derefOverriddenTableName.TableName())
		})
	}
}

func TestDerefAliases_clone(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	t.Run("valid", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		d, err := NewDerefAliases(testCtx, "test-id", DerefFindingBaseObj)
		require.NoError(err)
		cp := d.clone()
		assert.True(proto.Equal(cp.DerefAliases, d.DerefAliases))
	})
	t.Run("not-equal", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		d, err := NewDerefAliases(testCtx, "test-id", DerefFindingBaseObj)
		require.NoError(err)

		d2, err := NewDerefAliases(testCtx, "test-id", DerefAlways)
		require.NoError(err)

		cp := d.clone()
		assert.True(!proto.Equal(cp.DerefAliases, d2.DerefAliases))
	})
}
