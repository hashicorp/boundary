// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/apptoken/store"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestNewAppTokenGrant(t *testing.T) {
	t.Parallel()
	textCtx := context.Background()
	const (
		testAppTokenId = "app-token-id"
		testGrant      = "id=*;type=*;actions=*"
	)

	tests := []struct {
		name            string
		appTokenId      string
		grant           string
		want            *AppTokenGrant
		wantErrContains string
		wantErrMatch    *errors.Template
	}{
		{
			name:       "success",
			appTokenId: testAppTokenId,
			grant:      testGrant,
			want: &AppTokenGrant{
				AppTokenGrant: &store.AppTokenGrant{
					AppTokenId:     testAppTokenId,
					RawGrant:       testGrant,
					CanonicalGrant: testGrant,
				},
			},
		},
		{
			name:            "missing app token id",
			grant:           testGrant,
			wantErrContains: "missing app token id",
			wantErrMatch:    errors.T(errors.InvalidParameter),
		},
		{
			name:            "missing grant",
			appTokenId:      testAppTokenId,
			wantErrContains: "missing app token id",
			wantErrMatch:    errors.T(errors.InvalidParameter),
		},
		{
			name:            "invalid grant",
			appTokenId:      testAppTokenId,
			grant:           "id=*;type=*;actions=",
			wantErrContains: "parsing grant string",
			wantErrMatch:    errors.T(errors.InvalidParameter),
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewAppTokenGrant(textCtx, tc.appTokenId, tc.grant)
			if tc.wantErrContains != "" {
				require.Error(err)
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

func TestAppTokenGrant_clone(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	const (
		testAppTokenId = "app-token-id"
		testGrant      = "id=*;type=*;actions=*"
	)

	t.Run("valid", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		orig, err := NewAppTokenGrant(testCtx, testAppTokenId, testGrant)
		require.NoError(err)
		cp := orig.clone()
		assert.True(proto.Equal(cp.AppTokenGrant, orig.AppTokenGrant))
	})
	t.Run("not-equal", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		orig, err := NewAppTokenGrant(testCtx, testAppTokenId, testGrant)
		require.NoError(err)
		orig2, err := NewAppTokenGrant(testCtx, testAppTokenId+"+2", testGrant)
		require.NoError(err)

		cp := orig.clone()
		assert.True(!proto.Equal(cp.AppTokenGrant, orig2.AppTokenGrant))
	})
}

func TestAppTokenGrant_SetTableName(t *testing.T) {
	t.Parallel()
	defaultTableName := appTokenGrantTableName
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
			def := AllocAppTokenGrant()
			require.Equal(defaultTableName, def.TableName())
			m := AllocAppTokenGrant()
			m.SetTableName(tc.setNameTo)
			assert.Equal(tc.want, m.TableName())
		})
	}
}
