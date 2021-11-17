package controller

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/require"
)

func TestController_New(t *testing.T) {
	t.Run("ReconcileKeys", func(t *testing.T) {
		require := require.New(t)
		testCtx := context.Background()
		ctx, cancel := context.WithCancel(context.Background())
		tc := &TestController{
			t:      t,
			ctx:    ctx,
			cancel: cancel,
			opts:   nil,
		}
		conf := TestControllerConfig(t, ctx, tc, nil)

		// this tests a scenario where there is an audit DEK
		c, err := New(testCtx, conf)
		require.NoError(err)

		// this tests a scenario where there is NOT an audit DEK
		require.NoError(c.conf.Server.Database.Where("1=1").Delete(kms.AllocAuditKey()).Error)
		_, err = New(testCtx, conf)
		require.NoError(err)
	})
}
