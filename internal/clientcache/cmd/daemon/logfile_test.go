// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package daemon

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWithEventer(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	l, err := logFile(ctx, dir, 1)
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, l.Close())
	})

	var logLock sync.Mutex
	logger := hclog.New(&hclog.LoggerOptions{
		Output:     l,
		Level:      hclog.Debug,
		JSONFormat: false,
		Mutex:      &logLock,
	})
	require.NoError(t, event.InitFallbackLogger(logger))

	cfg := event.EventerConfig{
		AuditEnabled:        false,
		ObservationsEnabled: true,
		SysEventsEnabled:    true,
		Sinks: []*event.SinkConfig{
			{
				Name:       "default",
				EventTypes: []event.Type{event.EveryType},
				Format:     event.JSONHclogSinkFormat,
				Type:       event.WriterSink,
				WriterConfig: &event.WriterSinkTypeConfig{
					Writer: l,
				},
			},
		},
	}
	require.NoError(t, event.InitSysEventer(logger, &logLock, "test", event.WithEventerConfig(&cfg)))

	// Measured to have at least 1 record written in a rotated log file.
	for i := 0; i < 8129; i++ {
		event.WriteSysEvent(ctx, "test.caller", "this is a test event I am writing out.")
	}
	require.NoError(t, l.Close())
	ret, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(ret), 2)

	t.Run("new logfile valid event", func(t *testing.T) {
		out, err := os.ReadFile(filepath.Join(dir, logFileName))
		require.NoError(t, err)
		t.Logf("Got output of length %d", len(out))
		jd := json.NewDecoder(bytes.NewReader(out))
		m := make(map[string]interface{})
		assert.NoError(t, jd.Decode(&m), fmt.Sprintf("parsing %q", out))
	})
}

func TestRotation(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	l, err := logFile(ctx, dir, 1)
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, l.Close())
	})

	fi, err := os.Stat(filepath.Join(dir, logFileName))
	require.NoError(t, err)
	assert.Zero(t, fi.Size())
	assert.Equal(t, fs.FileMode(0o600), fi.Mode())

	// write 1 mb and see it all contained in a single log file
	toWrite := make([]byte, 1024)
	for i := 0; i < 1024; i++ {
		rand.Read(toWrite)
		_, err := l.Write(toWrite)
		require.NoError(t, err)
	}
	ret, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, ret, 1)
	assert.Equal(t, ret[0].Name(), logFileName)

	// write 1 more byte and see that it caused the log file to rotate
	_, err = l.Write([]byte("1"))
	require.NoError(t, err)

	ret, err = os.ReadDir(dir)
	require.NoError(t, err)
	// GreaterOrEqual is used here because while backups are compressed, both
	// the renamed backup .log and the log.gz files exist
	require.GreaterOrEqual(t, len(ret), 2)
	assert.True(t, strings.HasPrefix(ret[0].Name(), "cache"))
	assert.True(t, strings.HasPrefix(ret[1].Name(), "cache"))

	// write another 1 mb and see a third log file is created
	for i := 0; i < 1024; i++ {
		rand.Read(toWrite)
		_, err := l.Write(toWrite)
		require.NoError(t, err)
	}
	ret, err = os.ReadDir(dir)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(ret), 3)

	// and a 4th (3 backups plus the cache.log file)
	for i := 0; i < 1024; i++ {
		rand.Read(toWrite)
		_, err := l.Write(toWrite)
		require.NoError(t, err)
	}
	ret, err = os.ReadDir(dir)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(ret), 4)
}
