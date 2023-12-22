// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/apptoken/store"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestNewAppToken(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	testTime := time.Now().Truncate(time.Second)
	const (
		testCreatedBy   = "create-by"
		testScopeId     = "scope-id"
		testDescription = "description"
		testName        = "name"
	)

	tests := []struct {
		name            string
		scopeId         string
		expTime         time.Time
		createdBy       string
		opts            []Option
		want            *AppToken
		wantErrContains string
		wantErrMatch    *errors.Template
	}{
		{
			name:      "success-with-all-opts",
			scopeId:   testScopeId,
			expTime:   testTime,
			createdBy: testCreatedBy,
			opts: []Option{
				WithName(testCtx, testName),
				WithDescription(testCtx, testDescription),
			},
			want: &AppToken{
				AppToken: &store.AppToken{
					ScopeId:        testScopeId,
					ExpirationTime: &timestamp.Timestamp{Timestamp: timestamppb.New(testTime)},
					CreatedBy:      testCreatedBy,
					Name:           testName,
					Description:    testDescription,
				},
			},
		},
		{
			name:      "with-opt-err",
			scopeId:   testScopeId,
			expTime:   testTime,
			createdBy: testCreatedBy,
			opts: []Option{
				withOptError(testCtx),
			},
			wantErrContains: "with opt err",
			wantErrMatch:    errors.T(errors.Unknown),
		},
		{
			name:            "missing-scope-id",
			expTime:         testTime,
			createdBy:       testCreatedBy,
			wantErrContains: "missing scope id",
			wantErrMatch:    errors.T(errors.InvalidParameter),
		},
		{
			name:            "missing-created-by",
			scopeId:         testScopeId,
			expTime:         testTime,
			wantErrContains: "missing created by user",
			wantErrMatch:    errors.T(errors.InvalidParameter),
		},
		{
			name:            "missing-exp-time",
			scopeId:         testScopeId,
			createdBy:       testCreatedBy,
			wantErrContains: "missing expiration time",
			wantErrMatch:    errors.T(errors.InvalidParameter),
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewAppToken(testCtx, tc.scopeId, tc.expTime, tc.createdBy, tc.opts...)
			if tc.wantErrContains != "" {
				require.Error(err)
				assert.Contains(err.Error(), tc.wantErrContains)
				if tc.wantErrMatch != nil {
					assert.True(errors.Match(tc.wantErrMatch, err))
				}
				return
			}
			require.NoError(err)
			assert.Equal(tc.want, got)
		})
	}
}

func TestAppToken_clone(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	testTime := time.Now().Truncate(time.Second)
	const (
		testCreatedBy   = "create-by"
		testScopeId     = "scope-id"
		testDescription = "description"
		testName        = "name"
	)

	t.Run("valid", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		orig, err := NewAppToken(testCtx, testScopeId, testTime, testCreatedBy, WithName(testCtx, testName), WithDescription(testCtx, testDescription))
		require.NoError(err)
		cp := orig.clone()
		assert.True(proto.Equal(cp.AppToken, orig.AppToken))
	})
	t.Run("not-equal", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		orig, err := NewAppToken(testCtx, testScopeId, testTime, testCreatedBy, WithName(testCtx, testName), WithDescription(testCtx, testDescription))
		require.NoError(err)
		orig2, err := NewAppToken(testCtx, testScopeId+"+2", testTime, testCreatedBy+"+2", WithName(testCtx, testName+"+2"), WithDescription(testCtx, testDescription+"+2"))
		require.NoError(err)

		cp := orig.clone()
		assert.True(!proto.Equal(cp.AppToken, orig2.AppToken))
	})
}

func TestAppToken_SetTableName(t *testing.T) {
	t.Parallel()
	defaultTableName := appTokenTableName
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
			def := AllocAppToken()
			require.Equal(defaultTableName, def.TableName())
			m := AllocAppToken()
			m.SetTableName(tc.setNameTo)
			assert.Equal(tc.want, m.TableName())
		})
	}
}

func TestAppToken_oplog(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	testTk := &AppToken{
		AppToken: &store.AppToken{
			PublicId: "resource-public-id",
			ScopeId:  "scope-id",
		},
	}
	tests := []struct {
		name            string
		oplogType       oplog.OpType
		appTk           *AppToken
		want            oplog.Metadata
		wantErrContains string
		wantErrMatch    *errors.Template
	}{
		{
			name:      "oplog-create",
			oplogType: oplog.OpType_OP_TYPE_CREATE,
			appTk:     testTk,
			want: oplog.Metadata{
				"resource-public-id": []string{"resource-public-id"},
				"resource-type":      []string{"app token"},
				"op-type":            []string{oplog.OpType_OP_TYPE_CREATE.String()},
				"scope-id":           []string{"scope-id"},
			},
		},
		{
			name:            "invalid-oplog-type",
			appTk:           testTk,
			oplogType:       oplog.OpType_OP_TYPE_UNSPECIFIED,
			wantErrContains: "missing op type",
			wantErrMatch:    errors.T(errors.InvalidParameter),
		},
		{
			name:            "missing-app-token",
			oplogType:       oplog.OpType_OP_TYPE_CREATE,
			wantErrContains: "missing app token",
			wantErrMatch:    errors.T(errors.InvalidParameter),
		},
		{
			name: "missing-public-id",
			appTk: &AppToken{
				AppToken: &store.AppToken{
					ScopeId: "scope-id",
				},
			},
			oplogType:       oplog.OpType_OP_TYPE_CREATE,
			wantErrContains: "missing public id",
			wantErrMatch:    errors.T(errors.InvalidParameter),
		},
		{
			name: "missing-scope-id",
			appTk: &AppToken{
				AppToken: &store.AppToken{
					PublicId: "resource-public-id",
				},
			},
			oplogType:       oplog.OpType_OP_TYPE_CREATE,
			wantErrContains: "missing scope id",
			wantErrMatch:    errors.T(errors.InvalidParameter),
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := tc.appTk.oplog(testCtx, tc.oplogType)
			if tc.wantErrContains != "" {
				require.Error(err)
				assert.Contains(err.Error(), tc.wantErrContains)
				if tc.wantErrMatch != nil {
					assert.True(errors.Match(tc.wantErrMatch, err))
				}
				return
			}
			require.NoError(err)
			require.NotNil(got)
			assert.Equal(tc.want, got)
		})
	}
}
