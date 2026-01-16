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

func TestNewGroupEntrySearchConf(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	tests := []struct {
		name            string
		ctx             context.Context
		authMethodId    string
		opts            []Option
		want            *GroupEntrySearchConf
		wantErr         bool
		wantErrCode     errors.Code
		wantErrContains string
	}{
		{
			name:         "valid",
			ctx:          testCtx,
			authMethodId: "test-id",
			opts: []Option{
				WithGroupDn(testCtx, "dn"),
				WithGroupAttr(testCtx, "attr"),
				WithGroupFilter(testCtx, "filter"),
			},
			want: &GroupEntrySearchConf{
				GroupEntrySearchConf: &store.GroupEntrySearchConf{
					LdapMethodId: "test-id",
					GroupDn:      "dn",
					GroupAttr:    "attr",
					GroupFilter:  "filter",
				},
			},
		},
		{
			name:         "just-dn",
			ctx:          testCtx,
			authMethodId: "test-id",
			opts: []Option{
				WithGroupDn(testCtx, "dn"),
			},
			want: &GroupEntrySearchConf{
				GroupEntrySearchConf: &store.GroupEntrySearchConf{
					LdapMethodId: "test-id",
					GroupDn:      "dn",
				},
			},
		},
		{
			name:         "just-attr",
			ctx:          testCtx,
			authMethodId: "test-id",
			opts: []Option{
				WithGroupAttr(testCtx, "attr"),
			},
			want: &GroupEntrySearchConf{
				GroupEntrySearchConf: &store.GroupEntrySearchConf{
					LdapMethodId: "test-id",
					GroupAttr:    "attr",
				},
			},
		},
		{
			name:         "just-filter",
			ctx:          testCtx,
			authMethodId: "test-id",
			opts: []Option{
				WithGroupFilter(testCtx, "filter"),
			},
			want: &GroupEntrySearchConf{
				GroupEntrySearchConf: &store.GroupEntrySearchConf{
					LdapMethodId: "test-id",
					GroupFilter:  "filter",
				},
			},
		},
		{
			name:            "missing-auth-method-id",
			ctx:             testCtx,
			opts:            []Option{WithGroupDn(testCtx, "dn")},
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
			got, err := NewGroupEntrySearchConf(tc.ctx, tc.authMethodId, tc.opts...)
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

func TestGroupEntrySearchConf_SetTableName(t *testing.T) {
	t.Parallel()
	defaultTableName := groupEntrySearchConfTableName
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
			def := allocGroupEntrySearchConf()
			require.Equal(defaultTableName, def.TableName())
			m := allocGroupEntrySearchConf()
			m.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, m.TableName())
		})
	}
}

func TestGroupEntrySearchConf_clone(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	t.Run("valid", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		uc, err := NewGroupEntrySearchConf(testCtx, "test-id", WithGroupDn(testCtx, "dn"))
		require.NoError(err)
		cp := uc.clone()
		assert.True(proto.Equal(cp.GroupEntrySearchConf, uc.GroupEntrySearchConf))
	})
	t.Run("not-equal", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		uc, err := NewGroupEntrySearchConf(testCtx, "test-id", WithGroupDn(testCtx, "dn"))
		require.NoError(err)

		uc2, err := NewGroupEntrySearchConf(testCtx, "test-id", WithGroupDn(testCtx, "dn2"))
		require.NoError(err)

		cp := uc.clone()
		assert.True(!proto.Equal(cp.GroupEntrySearchConf, uc2.GroupEntrySearchConf))
	})
}
