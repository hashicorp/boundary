// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package schema

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/db/schema/internal/log"
	"github.com/hashicorp/boundary/internal/errors"
)

// LogEntry represents a log entry generated during migrations.
type LogEntry struct {
	Id               int
	MigrationVersion int
	MigrationEdition string
	CreateTime       time.Time
	Entry            string
}

// GetMigrationLog will retrieve the migration logs from the db for the last
// migration. Once it's read the entries, it will delete them from the database.
// The WithDeleteLog option is supported and will remove all log entries when provided.
func (b *Manager) GetMigrationLog(ctx context.Context, opt ...Option) ([]LogEntry, error) {
	const op = "schema.GetMigrationLog"

	var logOpts []log.Option
	opts := getOpts(opt...)
	if opts.withDeleteLog {
		logOpts = append(logOpts, log.WithDeleteLog(opts.withDeleteLog))
	}

	entries, err := b.driver.GetMigrationLog(ctx, logOpts...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	logEntries := make([]LogEntry, 0, len(entries))
	for _, e := range entries {
		logEntries = append(logEntries, LogEntry{
			Id:               e.Id,
			MigrationVersion: e.MigrationVersion,
			MigrationEdition: e.MigrationEdition,
			CreateTime:       e.CreateTime,
			Entry:            e.Entry,
		})
	}

	return logEntries, nil
}
