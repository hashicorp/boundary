// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package base

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/eventlogger/formatter_filters/cloudevents"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_oidcLogger_Errorf(t *testing.T) {
	// this test and its subtests cannot be run in parallel because of it's
	// dependency on the sysEventer

	c := event.TestEventerConfig(t, "TestoidcLogger_Errorf")
	testLock := &sync.Mutex{}
	testLogger := hclog.New(&hclog.LoggerOptions{
		Mutex: testLock,
		Name:  "test",
	})
	require.NoError(t, event.InitSysEventer(testLogger, testLock, "use-TestoidcLogger_Errorf", event.WithEventerConfig(&c.EventerConfig)))

	tests := []struct {
		name string
		fmt  string
		args []any
	}{
		{
			name: "no-args",
			fmt:  "simple",
		},
		{
			name: "with-args",
			fmt:  "%s: simple",
			args: []any{"error"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			l := &oidcLogger{}
			l.Errorf(tt.fmt, tt.args...)
			sinkFileName := c.AllEvents.Name()
			defer func() { _ = os.WriteFile(sinkFileName, nil, 0o666) }()
			b, err := os.ReadFile(sinkFileName)
			require.NoError(err)
			gotEvent := &cloudevents.Event{}
			err = json.Unmarshal(b, gotEvent)
			require.NoErrorf(err, "json: %s", string(b))
			expected := gotEvent.Data.(map[string]any)
			expected["error"] = fmt.Sprintf(tt.fmt, tt.args...)
			assert.Equal(expected, gotEvent.Data.(map[string]any))
		})
	}
}

func Test_oidcLogger_Infof(t *testing.T) {
	// this test and its subtests cannot be run in parallel because of it's
	// dependency on the sysEventer

	c := event.TestEventerConfig(t, "TestoidcLogger_Errorf")
	testLock := &sync.Mutex{}
	testLogger := hclog.New(&hclog.LoggerOptions{
		Mutex: testLock,
		Name:  "test",
	})
	require.NoError(t, event.InitSysEventer(testLogger, testLock, "use-TestoidcLogger_Errorf", event.WithEventerConfig(&c.EventerConfig)))

	tests := []struct {
		name string
		fmt  string
		args []any
	}{
		{
			name: "no-args",
			fmt:  "simple",
		},
		{
			name: "with-args",
			fmt:  "%s: simple",
			args: []any{"info"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			l := &oidcLogger{}
			l.Infof(tt.fmt, tt.args...)
			sinkFileName := c.AllEvents.Name()
			defer func() { _ = os.WriteFile(sinkFileName, nil, 0o666) }()
			b, err := os.ReadFile(sinkFileName)
			require.NoError(err)
			gotEvent := &cloudevents.Event{}
			err = json.Unmarshal(b, gotEvent)
			require.NoErrorf(err, "json: %s", string(b))
			expected := gotEvent.Data.(map[string]any)
			expected["msg"] = fmt.Sprintf(tt.fmt, tt.args...)
			assert.Equal(expected, gotEvent.Data.(map[string]any))
		})
	}
}

func Test_oidcLogger_FailNow(t *testing.T) {
	l := &oidcLogger{}
	assert.Panics(t, func() { l.FailNow() }, "sys eventer failed, see logs for output (if any)")
}
