// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ldap

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/auth/ldap/store"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewManagedGroup(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	tests := []struct {
		name            string
		ctx             context.Context
		authMethodId    string
		groupNames      []string
		opt             []Option
		want            *ManagedGroup
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name:         "success",
			ctx:          testCtx,
			authMethodId: "test-auth-method-id",
			groupNames:   []string{"admin"},
			opt:          []Option{WithName(testCtx, "success"), WithDescription(testCtx, "description")},
			want: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					Name:         "success",
					Description:  "description",
					AuthMethodId: "test-auth-method-id",
					GroupNames:   TestEncodedGrpNames(t, "admin"),
				},
			},
		},
		{
			name:            "missing-auth-method-id",
			ctx:             testCtx,
			groupNames:      []string{"admin"},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing auth method id",
		},
		{
			name:            "missing-group-names",
			ctx:             testCtx,
			authMethodId:    "test-auth-method-id",
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing group names",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewManagedGroup(tc.ctx, tc.authMethodId, tc.groupNames, tc.opt...)
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

func TestManagedGroup_SetTableName(t *testing.T) {
	t.Parallel()
	defaultTableName := managedGroupTableName
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
			def := AllocManagedGroup()
			require.Equal(defaultTableName, def.TableName())
			m := AllocManagedGroup()
			m.SetTableName(tc.setNameTo)
			assert.Equal(tc.want, m.TableName())
		})
	}
}

func TestManagedGroup_oplog(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	testMg, err := NewManagedGroup(testCtx, "test-id", []string{"admin"})
	testMg.PublicId = "test-public-id"
	require.NoError(t, err)
	tests := []struct {
		name            string
		ctx             context.Context
		mg              *ManagedGroup
		opType          oplog.OpType
		scopeId         string
		want            oplog.Metadata
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name:    "create",
			ctx:     testCtx,
			mg:      testMg,
			opType:  oplog.OpType_OP_TYPE_CREATE,
			scopeId: "global",
			want: oplog.Metadata{
				"auth-method-id":     {"test-id"},
				"resource-public-id": {"test-public-id"},
				"scope-id":           {"global"},
				"op-type":            {oplog.OpType_OP_TYPE_CREATE.String()},
				"resource-type":      {"ldap managed group"},
			},
		},
		{
			name:    "update",
			ctx:     testCtx,
			mg:      testMg,
			opType:  oplog.OpType_OP_TYPE_UPDATE,
			scopeId: "global",
			want: oplog.Metadata{
				"auth-method-id":     {"test-id"},
				"resource-public-id": {"test-public-id"},
				"scope-id":           {"global"},
				"op-type":            {oplog.OpType_OP_TYPE_UPDATE.String()},
				"resource-type":      {"ldap managed group"},
			},
		},
		{
			name: "missing-auth-method-id",
			ctx:  testCtx,
			mg: func() *ManagedGroup {
				cp := testMg.clone()
				cp.AuthMethodId = ""
				return cp
			}(),
			opType:          oplog.OpType_OP_TYPE_UPDATE,
			scopeId:         "global",
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing auth method id",
		},
		{
			name:            "missing-scope-id",
			ctx:             testCtx,
			mg:              testMg,
			opType:          oplog.OpType_OP_TYPE_UPDATE,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing scope id",
		},
		{
			name: "missing-public-id",
			ctx:  testCtx,
			mg: func() *ManagedGroup {
				cp := testMg.clone()
				cp.PublicId = ""
				return cp
			}(),
			opType:          oplog.OpType_OP_TYPE_UPDATE,
			scopeId:         "global",
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing public id",
		},
		{
			name:            "missing-op-type",
			ctx:             testCtx,
			mg:              testMg,
			scopeId:         "global",
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing op type",
		},
		{
			name:            "missing-managed-group",
			ctx:             testCtx,
			opType:          oplog.OpType_OP_TYPE_UPDATE,
			scopeId:         "global",
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing managed group",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := tc.mg.oplog(tc.ctx, tc.opType, tc.scopeId)
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
