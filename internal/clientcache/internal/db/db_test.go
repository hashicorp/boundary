// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package db

import (
	"context"
	"os"
	"sync"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"
)

func TestShowLoggingBehavior(t *testing.T) {
	ctx := context.Background()

	// This is just a placeholder test that can be modified and reviewed
	// manually to see that logging to the terminal stops when WithGormFormatter
	// is passed in regardless of the WithDebug option.
	t.Run("specifying gorm logger stops debug output", func(t *testing.T) {
		var logLock sync.Mutex
		logger := hclog.New(&hclog.LoggerOptions{
			Output:     os.Stdout,
			Level:      hclog.Trace,
			JSONFormat: false,
			Mutex:      &logLock,
		})
		_ = logger
		s, err := Open(ctx, WithDebug(true), WithGormFormatter(logger))
		require.NoError(t, err)

		logger.Debug("test message that should get written out")

		rw := db.New(s)
		rw.Query(ctx, "SELECT 1", nil, db.WithDebug(true))
	})
}
