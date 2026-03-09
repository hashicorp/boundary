// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package event

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEventer_Gating(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	buffer := new(bytes.Buffer)
	eventerConfig := EventerConfig{
		AuditEnabled:        true,
		ObservationsEnabled: true,
		SysEventsEnabled:    true,
		Sinks: []*SinkConfig{
			{
				Name:       "test-sink",
				EventTypes: []Type{EveryType},
				Format:     TextHclogSinkFormat,
				Type:       WriterSink,
				WriterConfig: &WriterSinkTypeConfig{
					Writer: buffer,
				},
			},
		},
	}
	testLock := &sync.Mutex{}
	testLogger := testLogger(t, testLock)

	eventer, err := NewEventer(
		testLogger,
		testLock,
		"TestEventer_Gating",
		eventerConfig,
		WithGating(true),
	)
	require.NoError(err)

	ctx, err := NewEventerContext(context.Background(), eventer)
	require.NoError(err)

	// This test sends a series of events of different types. The tests are
	// meant to be in order as we want to send some that should be gated and
	// some that shouldn't and ensure correct behavior at each step.
	var totalEvents int
	tests := []struct {
		name                string
		eventFn             func()
		expectedGatedEvents int
	}{
		{
			name: "system-event-1",
			eventFn: func() {
				WriteSysEvent(ctx, "system-event-1", "system-event-1")
				totalEvents++
			},
			expectedGatedEvents: 1,
		},
		{
			name: "system-event-2",
			eventFn: func() {
				WriteSysEvent(ctx, "system-event-2", "system-event-2")
				totalEvents++
			},
			expectedGatedEvents: 2,
		},
		{
			name: "audit-1",
			eventFn: func() {
				require.NoError(WriteAudit(ctx, "audit-1"))
				totalEvents++
			},
			expectedGatedEvents: 2,
		},
		{
			name: "observation-1",
			eventFn: func() {
				require.NoError(WriteObservation(ctx, "observation-1", WithId("observation-1"), WithHeader("foo", "bar")))
				totalEvents++
			},
			expectedGatedEvents: 2,
		},
		{
			name: "error-1",
			eventFn: func() {
				WriteError(ctx, "error-1", fmt.Errorf("error-1"))
				totalEvents++
			},
			expectedGatedEvents: 3,
		},
		{
			name: "error-2",
			eventFn: func() {
				WriteError(ctx, "error-2", fmt.Errorf("error-2"))
				totalEvents++
			},
			expectedGatedEvents: 4,
		},
		// This should result in all events being flushed so none gated
		{
			name: "release-gate",
			eventFn: func() {
				require.NoError(eventer.ReleaseGate())
			},
			expectedGatedEvents: 0,
		},
		// From here on out we're verifying that all events of all types go through
		{
			name: "system-event-3",
			eventFn: func() {
				WriteSysEvent(ctx, "system-event-3", "system-event-3")
				totalEvents++
			},
			expectedGatedEvents: 0,
		},
		{
			name: "audit-2",
			eventFn: func() {
				require.NoError(WriteAudit(ctx, "audit-2"))
				totalEvents++
			},
			expectedGatedEvents: 0,
		},
		{
			name: "observation-2",
			eventFn: func() {
				require.NoError(WriteObservation(ctx, "observation-2", WithId("observation-2"), WithHeader("foo", "bar")))
				totalEvents++
			},
			expectedGatedEvents: 0,
		},
		{
			name: "error-2",
			eventFn: func() {
				WriteError(ctx, "error-2", fmt.Errorf("error-2"))
				totalEvents++
			},
			expectedGatedEvents: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			tt.eventFn()
			assert.Len(strutil.RemoveEmpty(strings.Split(buffer.String(), "\n")), totalEvents-tt.expectedGatedEvents, buffer.String())
		})
	}
}

func TestReleaseGate_NoError_CanceledContext(t *testing.T) {
	require := require.New(t)

	buffer := new(bytes.Buffer)
	eventerConfig := EventerConfig{
		AuditEnabled:        true,
		ObservationsEnabled: true,
		SysEventsEnabled:    true,
		Sinks: []*SinkConfig{
			{
				Name:       "test-sink",
				EventTypes: []Type{EveryType},
				Format:     TextHclogSinkFormat,
				Type:       WriterSink,
				WriterConfig: &WriterSinkTypeConfig{
					Writer: buffer,
				},
			},
		},
	}
	testLock := &sync.Mutex{}
	testLogger := testLogger(t, testLock)

	eventer, err := NewEventer(
		testLogger,
		testLock,
		"TestEventer_Gating",
		eventerConfig,
		WithGating(true),
	)
	require.NoError(err)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ctx, err = NewEventerContext(ctx, eventer)
	require.NoError(err)

	WriteError(ctx, "error-1", fmt.Errorf("error-1"))
	_ = WriteObservation(ctx, "observation-1", WithId("observation-1"), WithHeader("foo", "bar"))

	cancel()

	require.NoError(eventer.ReleaseGate())
}
