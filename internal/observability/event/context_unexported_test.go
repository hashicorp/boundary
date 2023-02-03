// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package event

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_newSendCtx(t *testing.T) {
	testInfo := &RequestInfo{
		EventId: "test-id",
		Id:      "test-id",
	}
	tests := []struct {
		name       string
		ctx        context.Context
		wantCancel bool
		wantInfo   bool
	}{
		{
			name: "cancelled-with-info",
			ctx: func() context.Context {
				var err error
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				ctx, err = NewRequestInfoContext(ctx, testInfo)
				require.NoError(t, err)
				return ctx
			}(),
			wantCancel: true,
			wantInfo:   true,
		},
		{
			name: "cancelled-no-info",
			ctx: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				return ctx
			}(),
			wantCancel: true,
		},
		{
			name:     "no-info",
			ctx:      context.Background(),
			wantInfo: false,
		},
		{
			name: "with-info",
			ctx: func() context.Context {
				ctx, err := NewRequestInfoContext(context.Background(), testInfo)
				require.NoError(t, err)
				return ctx
			}(),
			wantInfo: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			ctx, cancel := newSendCtx(tt.ctx)
			require.NotNil(ctx)
			assert.True(ctx.Err() != context.Canceled)
			if tt.wantCancel {
				require.NotNil(cancel)
			} else {
				require.Nil(cancel)
			}
			info, ok := RequestInfoFromContext(ctx)
			if tt.wantInfo {
				assert.True(ok)
				assert.NotNil(info)
			} else {
				assert.False(ok)
				assert.Nil(info)
			}
		})
	}
}
