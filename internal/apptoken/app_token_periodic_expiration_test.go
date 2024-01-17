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

func TestNewAppTokenPeriodicExpirationInterval(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	const (
		testAppTokenId = "app-token-id"
		testInterval   = 10
	)

	tests := []struct {
		name            string
		appTokenId      string
		intervalSecs    uint32
		want            *AppTokenPeriodicExpirationInterval
		wantErrContains string
		wantErrMatch    *errors.Template
	}{
		{
			name:         "success-with-all-opts",
			appTokenId:   testAppTokenId,
			intervalSecs: testInterval,
			want: &AppTokenPeriodicExpirationInterval{
				AppTokenPeriodicExpirationInterval: &store.AppTokenPeriodicExpirationInterval{
					AppTokenId:                     testAppTokenId,
					ExpirationIntervalInMaxSeconds: testInterval,
				},
			},
		},
		{
			name:            "missing-app-token-id",
			intervalSecs:    testInterval,
			wantErrContains: "missing app token id",
			wantErrMatch:    errors.T(errors.InvalidParameter),
		},
		{
			name:            "invalid-max-seconds",
			appTokenId:      testAppTokenId,
			intervalSecs:    0,
			wantErrContains: "missing max seconds",
			wantErrMatch:    errors.T(errors.InvalidParameter),
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewAppTokenPeriodicExpirationInterval(testCtx, tc.appTokenId, tc.intervalSecs)
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

func TestAppTokenPeriodicExpirationInterval_clone(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	const (
		testAppTokenId = "test-app-token-id"
		testInterval   = 10
	)

	t.Run("valid", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		orig, err := NewAppTokenPeriodicExpirationInterval(testCtx, testAppTokenId, testInterval)
		require.NoError(err)
		cp := orig.clone()
		assert.True(proto.Equal(cp.AppTokenPeriodicExpirationInterval, orig.AppTokenPeriodicExpirationInterval))
	})
	t.Run("not-equal", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		orig, err := NewAppTokenPeriodicExpirationInterval(testCtx, testAppTokenId, uint32(testInterval))
		require.NoError(err)
		orig2, err := NewAppTokenPeriodicExpirationInterval(testCtx, testAppTokenId, uint32(testInterval+2))
		require.NoError(err)

		cp := orig.clone()
		assert.True(!proto.Equal(cp.AppTokenPeriodicExpirationInterval, orig2.AppTokenPeriodicExpirationInterval))
	})
}

func TestAppTokenPeriodicExpirationInterval_SetTableName(t *testing.T) {
	t.Parallel()
	defaultTableName := appTokenPeriodicExpirationTableName
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
			def := AllocAppTokenPeriodicExpirationInterval()
			require.Equal(defaultTableName, def.TableName())
			m := AllocAppTokenPeriodicExpirationInterval()
			m.SetTableName(tc.setNameTo)
			assert.Equal(tc.want, m.TableName())
		})
	}
}
