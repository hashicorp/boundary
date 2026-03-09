// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ldap

import (
	"context"
	"net/url"
	"testing"

	"github.com/hashicorp/boundary/internal/auth/ldap/store"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestNewUrl(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	tests := []struct {
		name            string
		ctx             context.Context
		authMethodId    string
		priority        int
		url             *url.URL
		want            *Url
		wantErr         bool
		wantErrCode     errors.Code
		wantErrContains string
	}{
		{
			name:         "valid",
			ctx:          testCtx,
			authMethodId: "test-id",
			priority:     10,
			url:          TestConvertToUrls(t, "ldaps://alice.com")[0],
			want: &Url{
				Url: &store.Url{
					LdapMethodId:       "test-id",
					ConnectionPriority: 10,
					ServerUrl:          "ldaps://alice.com",
				},
			},
		},
		{
			name:            "missing-auth-method-id",
			ctx:             testCtx,
			url:             TestConvertToUrls(t, "ldaps://alice.com")[0],
			wantErr:         true,
			wantErrCode:     errors.InvalidParameter,
			wantErrContains: "missing auth method id",
		},
		{
			name:            "missing-url",
			ctx:             testCtx,
			priority:        1,
			authMethodId:    "test-id",
			wantErr:         true,
			wantErrCode:     errors.InvalidParameter,
			wantErrContains: "missing url",
		},
		{
			name:         "invalid-scheme",
			ctx:          testCtx,
			authMethodId: "test-id",
			priority:     1,
			url: func() *url.URL {
				parsed, err := url.Parse("https://alice.com")
				require.NoError(t, err)
				return parsed
			}(),
			wantErr:         true,
			wantErrCode:     errors.InvalidParameter,
			wantErrContains: "scheme \"https\" is not ldap or ldaps",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewUrl(tc.ctx, tc.authMethodId, tc.priority, tc.url)
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

func TestUrl_SetTableName(t *testing.T) {
	t.Parallel()
	defaultTableName := urlTableName
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
			def := allocUrl()
			require.Equal(defaultTableName, def.TableName())
			m := allocUrl()
			m.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, m.TableName())
		})
	}
}

func TestUrl_clone(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	const priorityOfOne = 1
	t.Run("valid", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		u, err := NewUrl(testCtx, "test-id", priorityOfOne, TestConvertToUrls(t, "ldaps://alice.com")[0])
		require.NoError(err)
		cp := u.clone()
		assert.True(proto.Equal(cp.Url, u.Url))
	})
	t.Run("not-equal", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		u, err := NewUrl(testCtx, "test-id", priorityOfOne, TestConvertToUrls(t, "ldaps://alice.com")[0])
		require.NoError(err)

		u2, err := NewUrl(testCtx, "test-id", priorityOfOne, TestConvertToUrls(t, "ldaps://bob.com")[0])
		require.NoError(err)

		cp := u.clone()
		assert.True(!proto.Equal(cp.Url, u2.Url))
	})
}
