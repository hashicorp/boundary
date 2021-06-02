package event

import (
	"context"
	"os"
	"testing"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/eventlogger"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-multierror"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEventer_retrySend(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	testConfig := TestEventerConfig(t, "TestEventer_retrySend")

	eventer, err := NewEventer(hclog.Default(), testConfig.EventerConfig)
	require.NoError(t, err)

	testError := errors.New(errors.InvalidParameter, "missing-operation", "missing operation")
	testEvent, err := newError("TestEventer_retrySend", testError, WithId("test-error"))
	require.NoError(t, err)

	tests := []struct {
		name           string
		retries        uint
		backOff        backoff
		handler        sendHandler
		wantErrMatch   *errors.Template
		wantErrContain string
	}{
		{
			name:    "missing-backoff",
			retries: 1,
			handler: func() (eventlogger.Status, error) {
				return eventer.broker.Send(ctx, eventlogger.EventType(ErrorType), testEvent)
			},
			wantErrMatch:   errors.T(errors.InvalidParameter),
			wantErrContain: "missing backoff",
		},
		{
			name:           "missing-handler",
			retries:        1,
			backOff:        expBackoff{},
			wantErrMatch:   errors.T(errors.InvalidParameter),
			wantErrContain: "missing handler",
		},
		{
			name:    "too-many-retries",
			retries: 3,
			backOff: expBackoff{},
			handler: func() (eventlogger.Status, error) {
				return eventlogger.Status{}, errors.New(errors.InvalidParameter, "TestEventer_retrySend", "will never work")
			},
			wantErrMatch:   errors.T(errors.MaxRetries),
			wantErrContain: "Too many retries",
		},
		{
			name:    "success-with-warnings",
			retries: 3,
			backOff: expBackoff{},
			handler: func() (eventlogger.Status, error) {
				return eventlogger.Status{
					Warnings: []error{errors.New(errors.RecordNotFound, "TestEventer_retrySend", "not found")},
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
			if tt.wantErrMatch != nil {
				require.Error(err)
				multi, isMultiError := err.(*multierror.Error)
				switch isMultiError {
				case true:
					matched := false
					for _, e := range multi.WrappedErrors() {
						if errors.Match(tt.wantErrMatch, e) {
							if tt.wantErrContain != "" {
								assert.Contains(err.Error(), tt.wantErrContain)
							}
							matched = true
						}
					}
					assert.True(matched)
				default:
					assert.True(errors.Match(tt.wantErrMatch, err))
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
