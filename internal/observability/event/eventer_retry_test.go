package event

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/hashicorp/eventlogger"
	"github.com/hashicorp/go-multierror"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEventer_retrySend(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	testConfig := TestEventerConfig(t, "TestEventer_retrySend")

	testLock := &sync.Mutex{}
	testLogger := testLogger(t, testLock)

	eventer, err := NewEventer(testLogger, testLock, "TestEventer_retrySend", testConfig.EventerConfig)
	require.NoError(t, err)

	testError := fmt.Errorf("%s: missing operation: %w", "missing operation", ErrInvalidParameter)
	testEvent, err := newError("TestEventer_retrySend", testError, WithId("test-error"))
	require.NoError(t, err)

	tests := []struct {
		name           string
		retries        uint
		backOff        backoff
		handler        sendHandler
		wantErrIs      error
		wantErrContain string
	}{
		{
			name:    "missing-backoff",
			retries: 1,
			handler: func() (eventlogger.Status, error) {
				return eventer.broker.Send(ctx, eventlogger.EventType(ErrorType), testEvent)
			},
			wantErrIs:      ErrInvalidParameter,
			wantErrContain: "missing backoff",
		},
		{
			name:           "missing-handler",
			retries:        1,
			backOff:        expBackoff{},
			wantErrIs:      ErrInvalidParameter,
			wantErrContain: "missing handler",
		},
		{
			name:    "too-many-retries",
			retries: 3,
			backOff: expBackoff{},
			handler: func() (eventlogger.Status, error) {
				return eventlogger.Status{}, fmt.Errorf("%s: will never work: %w", "TestEventer_retrySend", ErrMaxRetries)
			},
			wantErrIs:      ErrMaxRetries,
			wantErrContain: "too many retries",
		},
		{
			name:    "success-with-warnings",
			retries: 3,
			backOff: expBackoff{},
			handler: func() (eventlogger.Status, error) {
				return eventlogger.Status{
					Warnings: []error{fmt.Errorf("%s: not found: %w", "TestEventer_retrySend", ErrRecordNotFound)},
				}, nil
			},
		},
		{
			name:    "success",
			retries: 1,
			backOff: expBackoff{},
			handler: func() (eventlogger.Status, error) {
				return eventlogger.Status{}, nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			defer os.Remove(testConfig.AllEvents.Name())
			defer os.Remove(testConfig.ErrorEvents.Name())

			err := eventer.retrySend(ctx, tt.retries, tt.backOff, tt.handler)
			if tt.wantErrIs != nil {
				require.Error(err)
				multi, isMultiError := err.(*multierror.Error)
				switch isMultiError {
				case true:
					matched := false
					for _, e := range multi.WrappedErrors() {
						if assert.ErrorIs(e, tt.wantErrIs) {
							if tt.wantErrContain != "" {
								assert.Contains(err.Error(), tt.wantErrContain)
							}
							matched = true
						}
					}
					assert.True(matched)
				default:
					assert.ErrorIs(err, tt.wantErrIs)
					if tt.wantErrContain != "" {
						assert.Contains(err.Error(), tt.wantErrContain)
					}
				}
				return
			}
			require.NoError(err)
		})
	}
}
