// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package billing

import (
	"context"
	"database/sql"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
)

// A Repository retrieves the persistent type in the billing
// package. It is not safe to use a repository concurrently.
// It provides a method for requesting pre-aggregated user counts
// per month. Depending on whether a start time and/or end time are given,
// an ActiveUsers object will be returned:
//   - for every month from the provided start date until the present date,
//     with the present date being a cumulative count up to the present date.
//   - for every month from the provided start date until the provided end date.
//   - for the previous month and current month, with the current month being a
//     cumulative count up to the present date.
type Repository struct {
	reader db.Reader
}

// NewRepository creates a new Repository. The returned repository is not safe for concurrent go
// routines to access it.
func NewRepository(ctx context.Context, r db.Reader) (*Repository, error) {
	const op = "billing.NewRepository"
	switch {
	case r == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil db reader")
	}

	return &Repository{
		reader: r,
	}, nil
}

// MonthlyActiveUsers returns the active users for a range of months, from most recent to least.
// If no start or end time is provided, it will return the active users for the last two months.
// If a start time is provided, it will return the active users for that month until the current month.
// If both a start and end time are provided, it will return the active users for that time range,
// starting time inclusive and ending time exclusive.
// The times provided must be the start of the month at midnight UTC.
func (r *Repository) MonthlyActiveUsers(ctx context.Context, opt ...Option) ([]ActiveUsers, error) {
	const op = "billing.Repository.MonthlyActiveUsers"

	opts := getOpts(opt...)

	switch {
	case opts.withEndTime != nil && opts.withStartTime == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "end time set without start time")
	case opts.withEndTime != nil && !opts.withEndTime.After(*opts.withStartTime):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "start time is not before end time")
	}
	query := activeUsersLastTwoMonthsQuery
	var args []any
	if opts.withStartTime != nil {
		if *opts.withStartTime != time.Date(opts.withStartTime.Year(), opts.withStartTime.Month(), 1, 0, 0, 0, 0, time.UTC) {
			return nil, errors.New(ctx, errors.InvalidParameter, op, "start time must be the first day of the month at midnight UTC")
		}
		query = activeUsersWithStartTimeQuery
		args = append(args,
			sql.Named("start_time", timestamp.New(*opts.withStartTime)))
	}
	if opts.withEndTime != nil {
		if *opts.withEndTime != time.Date(opts.withEndTime.Year(), opts.withEndTime.Month(), 1, 0, 0, 0, 0, time.UTC) {
			return nil, errors.New(ctx, errors.InvalidParameter, op, "end time must be the first day of the month at midnight UTC")
		}
		query = activeUsersWithStartTimeAndEndTimeQuery
		args = append(args,
			sql.Named("end_time", timestamp.New(*opts.withEndTime)))
	}

	var activeUsers []ActiveUsers
	rows, err := r.reader.Query(ctx, query, args)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for rows.Next() {
		var startTime time.Time
		var endTime time.Time
		var count uint32
		if err := rows.Scan(&startTime, &endTime, &count); err != nil {
			return nil, err
		}

		// set start and end times to be in UTC
		auUTC := ActiveUsers{
			ActiveUsersCount: count,
			StartTime:        startTime.UTC(),
			EndTime:          endTime.UTC(),
		}
		activeUsers = append(activeUsers, auUTC)
	}

	return activeUsers, nil
}
