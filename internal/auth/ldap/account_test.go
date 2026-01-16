// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ldap

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth/ldap/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestNewAccount(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	testAuthMethodId := fmt.Sprintf("%s_1", globals.LdapAuthMethodPrefix)
	tests := []struct {
		name            string
		ctx             context.Context
		scopeId         string
		authMethodId    string
		loginName       string
		opt             []Option
		want            *Account
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name:         "success-with-all-opts",
			ctx:          testCtx,
			scopeId:      "global",
			authMethodId: testAuthMethodId,
			loginName:    "test-login-name",
			opt: []Option{
				WithName(testCtx, "test-name"),
				WithDescription(testCtx, "test-description"),
				WithEmail(testCtx, "alice@bob.com"),
				WithFullName(testCtx, "alice eve smith"),
				WithDn(testCtx, "uid=alice, ou=people, o=test org"),
				WithMemberOfGroups(testCtx, "test-group"),
			},
			want: &Account{
				Account: &store.Account{
					AuthMethodId:   testAuthMethodId,
					ScopeId:        "global",
					LoginName:      "test-login-name",
					Name:           "test-name",
					Description:    "test-description",
					Email:          "alice@bob.com",
					FullName:       "alice eve smith",
					Dn:             "uid=alice, ou=people, o=test org",
					MemberOfGroups: "[\"test-group\"]",
				},
			},
		},
		{
			name:            "missing-scope-id",
			ctx:             testCtx,
			authMethodId:    testAuthMethodId,
			loginName:       "test-login-name",
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing scope id",
		},
		{
			name:            "missing-auth-method-id",
			ctx:             testCtx,
			scopeId:         "global",
			loginName:       "test-login-name",
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing auth method id",
		},
		{
			name:            "missing-login-name",
			ctx:             testCtx,
			scopeId:         "global",
			authMethodId:    testAuthMethodId,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing login name",
		},
		{
			name:            "validate-err",
			ctx:             testCtx,
			scopeId:         "global",
			authMethodId:    testAuthMethodId,
			loginName:       "test-login-name",
			opt:             []Option{WithEmail(testCtx, strings.Repeat("-", 400))},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "email address is too long",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewAccount(tc.ctx, tc.scopeId, tc.authMethodId, tc.loginName, tc.opt...)
			if tc.wantErrMatch != nil {
				require.Error(err)
				assert.Nil(got)
				assert.True(errors.Match(tc.wantErrMatch, err))
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

func TestAccount_clone(t *testing.T) {
	t.Parallel()
	testCtx := context.TODO()
	testConn, _ := db.TestSetup(t, "postgres")
	testWrapper := db.TestWrapper(t)

	t.Run("valid", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		org, _ := iam.TestScopes(t, iam.TestRepo(t, testConn, testWrapper))
		m := TestAuthMethod(t, testConn, testWrapper, org.PublicId, []string{"ldaps://ldap1"})
		orig, err := NewAccount(testCtx, m.ScopeId, m.PublicId, "alice", WithFullName(testCtx, "Alice Eve Smith"), WithEmail(testCtx, "alice@alice.com"))
		require.NoError(err)
		cp := orig.clone()
		assert.True(proto.Equal(cp.Account, orig.Account))
	})
	t.Run("not-equal", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		org, _ := iam.TestScopes(t, iam.TestRepo(t, testConn, testWrapper))
		m := TestAuthMethod(t, testConn, testWrapper, org.PublicId, []string{"ldaps://ldap1"})
		orig, err := NewAccount(testCtx, m.ScopeId, m.PublicId, "alice", WithFullName(testCtx, "Alice Eve Smith"), WithEmail(testCtx, "alice@alice.com"))
		require.NoError(err)
		orig2, err := NewAccount(testCtx, m.ScopeId, m.PublicId, "bob", WithFullName(testCtx, "Bob Eve Smith"), WithEmail(testCtx, "bob@alice.com"))
		require.NoError(err)

		cp := orig.clone()
		assert.True(!proto.Equal(cp.Account, orig2.Account))
	})
}

func TestAccount_SetTableName(t *testing.T) {
	t.Parallel()
	defaultTableName := accountTableName
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
			def := AllocAccount()
			require.Equal(defaultTableName, def.TableName())
			m := AllocAccount()
			m.SetTableName(tc.setNameTo)
			assert.Equal(tc.want, m.TableName())
		})
	}
}

func TestAccount_oplog(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	testAcct, err := NewAccount(testCtx, "global", "test-id", "test-login-name")
	testAcct.PublicId = "test-public-id"
	require.NoError(t, err)
	tests := []struct {
		name            string
		ctx             context.Context
		acct            *Account
		opType          oplog.OpType
		want            oplog.Metadata
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name:   "create",
			ctx:    testCtx,
			acct:   testAcct,
			opType: oplog.OpType_OP_TYPE_CREATE,
			want: oplog.Metadata{
				"auth-method-id":     {"test-id"},
				"resource-public-id": {"test-public-id"},
				"scope-id":           {"global"},
				"op-type":            {oplog.OpType_OP_TYPE_CREATE.String()},
				"resource-type":      {"ldap account"},
			},
		},
		{
			name:   "update",
			ctx:    testCtx,
			acct:   testAcct,
			opType: oplog.OpType_OP_TYPE_UPDATE,
			want: oplog.Metadata{
				"auth-method-id":     {"test-id"},
				"resource-public-id": {"test-public-id"},
				"scope-id":           {"global"},
				"op-type":            {oplog.OpType_OP_TYPE_UPDATE.String()},
				"resource-type":      {"ldap account"},
			},
		},
		{
			name: "missing-auth-method-id",
			ctx:  testCtx,
			acct: func() *Account {
				cp := testAcct.clone()
				cp.AuthMethodId = ""
				return cp
			}(),
			opType:          oplog.OpType_OP_TYPE_UPDATE,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing auth method id",
		},
		{
			name: "missing-scope-id",
			ctx:  testCtx,
			acct: func() *Account {
				cp := testAcct.clone()
				cp.ScopeId = ""
				return cp
			}(),
			opType:          oplog.OpType_OP_TYPE_UPDATE,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing scope id",
		},
		{
			name: "missing-public-id",
			ctx:  testCtx,
			acct: func() *Account {
				cp := testAcct.clone()
				cp.PublicId = ""
				return cp
			}(),
			opType:          oplog.OpType_OP_TYPE_UPDATE,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing public id",
		},
		{
			name:            "missing-op-type",
			ctx:             testCtx,
			acct:            testAcct,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing op type",
		},
		{
			name:            "missing-account",
			ctx:             testCtx,
			opType:          oplog.OpType_OP_TYPE_UPDATE,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing account",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := tc.acct.oplog(tc.ctx, tc.opType)
			if tc.wantErrMatch != nil {
				require.Error(err)
				assert.Nil(got)
				assert.True(errors.Match(tc.wantErrMatch, err))
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

func TestAccount_GetAuthMethodId(t *testing.T) {
	t.Parallel()
	assert.Empty(t, AllocAccount().GetAuthMethodId())
}

func TestAccount_GetSubject(t *testing.T) {
	t.Parallel()
	assert.Empty(t, AllocAccount().GetSubject())
}

func TestAccount_validate(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	tests := []struct {
		name            string
		ctx             context.Context
		caller          errors.Op
		acct            *Account
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name: "missing-caller",
			ctx:  testCtx,
			acct: func() *Account {
				a, err := NewAccount(testCtx, "global", "test-auth-method-id", "test-login-name")
				require.NoError(t, err)
				return a
			}(),
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing caller",
		},
		{
			name:   "missing-scope-id",
			ctx:    testCtx,
			caller: "test",
			acct: func() *Account {
				a, err := NewAccount(testCtx, "global", "test-auth-method-id", "test-login-name")
				require.NoError(t, err)
				a.ScopeId = ""
				return a
			}(),
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing scope id",
		},
		{
			name:   "missing-auth-method-id",
			ctx:    testCtx,
			caller: "test",
			acct: func() *Account {
				a, err := NewAccount(testCtx, "global", "test-auth-method-id", "test-login-name")
				require.NoError(t, err)
				a.AuthMethodId = ""
				return a
			}(),
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing auth method id",
		},
		{
			name:   "missing-login-name",
			ctx:    testCtx,
			caller: "test",
			acct: func() *Account {
				a, err := NewAccount(testCtx, "global", "test-auth-method-id", "test-login-name")
				require.NoError(t, err)
				a.LoginName = ""
				return a
			}(),
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing login name",
		},
		{
			name:   "email-too-long",
			ctx:    testCtx,
			caller: "test",
			acct: func() *Account {
				a, err := NewAccount(testCtx, "global", "test-auth-method-id", "test-login-name")
				require.NoError(t, err)
				a.Email = strings.Repeat("-", 321)
				return a
			}(),
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "email address is too long",
		},
		{
			name:   "full-name-too-long",
			ctx:    testCtx,
			caller: "test",
			acct: func() *Account {
				a, err := NewAccount(testCtx, "global", "test-auth-method-id", "test-login-name")
				require.NoError(t, err)
				a.FullName = strings.Repeat("-", 513)
				return a
			}(),
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "full name is too long",
		},
		{
			name:   "login-name-not-lower-case",
			ctx:    testCtx,
			caller: "test",
			acct: func() *Account {
				a, err := NewAccount(testCtx, "global", "test-auth-method-id", "test-login-name")
				require.NoError(t, err)
				a.LoginName = "Test-Login-Name"
				return a
			}(),
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "login name must be lower case",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			err := tc.acct.validate(tc.ctx, tc.caller)
			if tc.wantErrMatch != nil {
				require.Error(err)
				assert.True(errors.Match(tc.wantErrMatch, err))
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
		})
	}
}
