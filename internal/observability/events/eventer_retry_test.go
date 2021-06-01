package event

import (
	"context"
	"os"
	"testing"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEventer_retrySend(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	testConfig := TestEventerConfig(t, "retrySend")
	eventer, err := NewEventer(hclog.Default(), testConfig.EventerConfig)
	require.NoError(t, err)

	tests := []struct {
		name         string
		retries      uint
		backOff      backoff
		handler      sendHandler
		wantErrMatch *errors.Template
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			defer os.Remove(testConfig.AllEvents.Name())
			defer os.Remove(testConfig.ErrorEvents.Name())

			err := eventer.retrySend(ctx, tt.retries, tt.backOff, tt.handler)
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.True(errors.Match(tt.wantErrMatch, err))
				return
			}
			require.NoError(err)

		})
	}
}
