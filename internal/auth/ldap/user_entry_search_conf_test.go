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

func TestNewUserEntrySearchConf(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	tests := []struct {
		name            string
		ctx             context.Context
		authMethodId    string
		opts            []Option
		want            *UserEntrySearchConf
		wantErr         bool
		wantErrCode     errors.Code
		wantErrContains string
	}{
		{
			name:         "valid",
			ctx:          testCtx,
			authMethodId: "test-id",
			opts: []Option{
				WithUserDn(testCtx, "dn"),
				WithUserAttr(testCtx, "attr"),
				WithUserFilter(testCtx, "filter"),
			},
			want: &UserEntrySearchConf{
				UserEntrySearchConf: &store.UserEntrySearchConf{
					LdapMethodId: "test-id",
					UserDn:       "dn",
					UserAttr:     "attr",
					UserFilter:   "filter",
				},
			},
		},
		{
			name:         "just-dn",
			ctx:          testCtx,
			authMethodId: "test-id",
			opts: []Option{
				WithUserDn(testCtx, "dn"),
			},
			want: &UserEntrySearchConf{
				UserEntrySearchConf: &store.UserEntrySearchConf{
					LdapMethodId: "test-id",
					UserDn:       "dn",
				},
			},
		},
		{
			name:         "just-attr",
			ctx:          testCtx,
			authMethodId: "test-id",
			opts: []Option{
				WithUserAttr(testCtx, "attr"),
			},
			want: &UserEntrySearchConf{
				UserEntrySearchConf: &store.UserEntrySearchConf{
					LdapMethodId: "test-id",
					UserAttr:     "attr",
				},
			},
		},
		{
			name:         "just-filter",
			ctx:          testCtx,
			authMethodId: "test-id",
			opts: []Option{
				WithUserFilter(testCtx, "filter"),
			},
			want: &UserEntrySearchConf{
				UserEntrySearchConf: &store.UserEntrySearchConf{
					LdapMethodId: "test-id",
					UserFilter:   "filter",
				},
			},
		},
		{
			name:            "missing-auth-method-id",
			ctx:             testCtx,
			opts:            []Option{WithUserDn(testCtx, "dn")},
			wantErr:         true,
			wantErrCode:     errors.InvalidParameter,
			wantErrContains: "missing auth method id",
		},
		{
			name:            "no-opts",
			ctx:             testCtx,
			authMethodId:    "test-id",
			wantErr:         true,
			wantErrCode:     errors.InvalidParameter,
			wantErrContains: "you must supply either dn, attr, or filter",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewUserEntrySearchConf(tc.ctx, tc.authMethodId, tc.opts...)
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

func TestUserEntrySearchConf_SetTableName(t *testing.T) {
	t.Parallel()
	defaultTableName := userEntrySearchConfTableName
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
			def := allocUserEntrySearchConf()
			require.Equal(defaultTableName, def.TableName())
			m := allocUserEntrySearchConf()
			m.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, m.TableName())
		})
	}
}

func TestUserEntrySearchCon_clone(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	t.Run("valid", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		uc, err := NewUserEntrySearchConf(testCtx, "test-id", WithUserDn(testCtx, "dn"))
		require.NoError(err)
		cp := uc.clone()
		assert.True(proto.Equal(cp.UserEntrySearchConf, uc.UserEntrySearchConf))
	})
	t.Run("not-equal", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		uc, err := NewUserEntrySearchConf(testCtx, "test-id", WithUserDn(testCtx, "dn"))
		require.NoError(err)

		uc2, err := NewUserEntrySearchConf(testCtx, "test-id", WithUserDn(testCtx, "dn2"))
		require.NoError(err)

		cp := uc.clone()
		assert.True(!proto.Equal(cp.UserEntrySearchConf, uc2.UserEntrySearchConf))
	})
}
