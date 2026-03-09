// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ldap

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/internal/auth/ldap/store"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestNewAccountAttributeMap(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	tests := []struct {
		name            string
		ctx             context.Context
		authMethodId    string
		from            string
		to              AccountToAttribute
		want            *AccountAttributeMap
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name:         "success",
			ctx:          testCtx,
			authMethodId: "test-auth-method-id",
			from:         "mail",
			to:           ToEmailAttribute,
			want: &AccountAttributeMap{
				AccountAttributeMap: &store.AccountAttributeMap{
					LdapMethodId:  "test-auth-method-id",
					FromAttribute: "mail",
					ToAttribute:   string(ToEmailAttribute),
				},
			},
		},
		{
			name:            "missing-auth-method-id",
			ctx:             testCtx,
			from:            "mail",
			to:              ToEmailAttribute,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing ldap auth method id",
		},
		{
			name:            "missing-from",
			ctx:             testCtx,
			authMethodId:    "test-auth-method-id",
			to:              ToEmailAttribute,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing from attribute",
		},
		{
			name:            "missing-to",
			ctx:             testCtx,
			authMethodId:    "test-auth-method-id",
			from:            "mail",
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "\"\" is not a valid ToAccountAttribute value",
		},
		{
			name:            "invalid-to",
			ctx:             testCtx,
			authMethodId:    "test-auth-method-id",
			from:            "mail",
			to:              "invalid-to",
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "\"invalid-to\" is not a valid ToAccountAttribute value",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewAccountAttributeMap(tc.ctx, tc.authMethodId, tc.from, tc.to)
			if tc.wantErrMatch != nil {
				require.Error(err)
				assert.Empty(got)
				assert.Truef(errors.Match(tc.wantErrMatch, err), "unexpected error: %q", err.Error())
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			require.NotNil(got)
			assert.Equal(tc.want, got)
		})
	}
}

func TestAccountAttributeMap_Clone(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	t.Run("valid", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		orig, err := NewAccountAttributeMap(testCtx, "test-scope-id", "displayName", ToFullNameAttribute)
		require.NoError(err)
		cp := orig.clone()
		assert.True(proto.Equal(cp.AccountAttributeMap, orig.AccountAttributeMap))
	})
	t.Run("not-equal", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		orig, err := NewAccountAttributeMap(testCtx, "test-scope-id", "displayName", ToFullNameAttribute)
		require.NoError(err)
		orig2, err := NewAccountAttributeMap(testCtx, "test-scope-id", "displayName2", ToFullNameAttribute)
		require.NoError(err)

		cp := orig.clone()
		assert.True(!proto.Equal(cp.AccountAttributeMap, orig2.AccountAttributeMap))
	})
}

func TestAccountAttributeMap_SetTableName(t *testing.T) {
	t.Parallel()
	defaultTableName := acctAttributeMapTableName
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
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			def := AllocAccountAttributeMap()
			require.Equal(defaultTableName, def.TableName())
			m := AllocAccountAttributeMap()
			m.SetTableName(tc.setNameTo)
			assert.Equal(tc.want, m.TableName())
		})
	}
}

func TestParseAccountAttributeMaps(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	tests := []struct {
		name            string
		ctx             context.Context
		attrMaps        []string
		want            []AttributeMap
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name:            "dup-to-attribute",
			ctx:             testCtx,
			attrMaps:        []string{"from=email", "from=email"},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "duplicate map for \"email\" attribute",
		},
		{
			name:     "dup-from-attribute",
			ctx:      testCtx,
			attrMaps: []string{"from=email", "from=fullName"},
			want: []AttributeMap{
				{To: "email", From: "from"},
				{To: "fullName", From: "from"},
			},
		},
		{
			name:            "two-equals",
			ctx:             testCtx,
			attrMaps:        []string{"from==email"},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "\"=email\" is not a valid ToAccountAttribute",
		},
		{
			name:            "invalid-parts",
			ctx:             testCtx,
			attrMaps:        []string{"from=e=mail"},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "\"e=mail\" is not a valid ToAccountAttribute",
		},
		{
			name:     "missing-separators",
			ctx:      testCtx,
			attrMaps: []string{"from/email"},

			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "error parsing attribute map \"from/email\": format must be key=value",
		},
		{
			name:     "simple",
			ctx:      testCtx,
			attrMaps: []string{"from=email"},
			want: []AttributeMap{
				{To: "email", From: "from"},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := ParseAccountAttributeMaps(tc.ctx, tc.attrMaps...)
			if tc.wantErrMatch != nil {
				require.Error(err)
				assert.Empty(got)
				assert.True(errors.Match(tc.wantErrMatch, err))
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			require.NotEmpty(got)
			assert.Equal(tc.want, got)
		})
	}
}

func FuzzParseAccountAttributeMaps(f *testing.F) {
	reverseFn := func(am AttributeMap) string {
		return fmt.Sprintf("%s=%s", am.From, am.To)
	}
	testCtx := context.Background()
	f.Add("mail=email")
	f.Add("displayName=fullName")
	f.Fuzz(func(t *testing.T, m string) {
		am, err := ParseAccountAttributeMaps(testCtx, m)
		if err != nil {
			return
		}
		if len(am) != 1 {
			return
		}
		reversed := reverseFn(am[0])
		if reversed != m {
			t.Errorf("account attribute roundtrip failed, input %q, output %q", m, reversed)
		}
	})
}
