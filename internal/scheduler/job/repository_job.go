// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package job

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
)

// UpsertJob inserts a job into the repository or updates its current description
// and returns a new *Job.
//
// • name must be provided and is the name of the job.
//
// • description must be provided and is the user-friendly description of the job.
//
// WithNextRunIn is the only valid options.
func (r *Repository) UpsertJob(ctx context.Context, name, description string, opt ...Option) (*Job, error) {
	const op = "job.(Repository).UpsertJob"
	if name == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing name")
	}
	if description == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing description")
	}

	opts := getOpts(opt...)

	defaultId := defaultPluginId

	j := allocJob()
	_, err := r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(r db.Reader, w db.Writer) error {
			rows, err := r.Query(ctx, upsertJobQuery, []any{
				sql.Named("plugin_id", defaultId),
				sql.Named("name", name),
				sql.Named("description", description),
				sql.Named("next_scheduled_run", int(opts.withNextRunIn.Round(time.Second).Seconds())),
			})
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithoutEvent())
			}
			defer rows.Close()

			var rowCnt int
			for rows.Next() {
				if rowCnt > 0 {
					return errors.New(ctx, errors.MultipleRecords, op, "more than 1 job would have been created", errors.WithoutEvent())
				}
				rowCnt++
				err = r.ScanRows(ctx, rows, j)
				if err != nil {
					_ = rows.Close()
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to scan rows for job"), errors.WithoutEvent())
				}
			}
			if err := rows.Err(); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get next row for job"), errors.WithoutEvent())
			}
			if rowCnt == 0 {
				return errors.New(ctx, errors.NotSpecificIntegrity, op, "failed to create new job", errors.WithoutEvent())
			}

			return nil
		},
	)
	if err != nil {
		if errors.IsUniqueError(err) {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("name %s already exists", name)), errors.WithoutEvent())
		}
		return nil, errors.Wrap(ctx, err, op)
	}
	return j, nil
}

// UpdateJobNextRunInAtLeast updates the Job repository entry for the job name,
// setting the job's NextScheduledRun time to either the current database time incremented by
// the nextRunInAtLeast parameter or the current NextScheduledRun time value, which ever is sooner.
//
// All options are ignored.
func (r *Repository) UpdateJobNextRunInAtLeast(ctx context.Context, name string, nextRunInAtLeast time.Duration, _ ...Option) (*Job, error) {
	const op = "job.(Repository).UpdateJobNextRunInAtLeast"
	if name == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing name")
	}

	j := allocJob()
	_, err := r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(r db.Reader, w db.Writer) error {
			rows, err := w.Query(ctx, setNextScheduledRunIfSoonerQuery, []any{int(nextRunInAtLeast.Round(time.Second).Seconds()), defaultPluginId, name})
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg(
					fmt.Sprintf("failed to set next scheduled run time for job %v", name)))
			}
			defer rows.Close()

			var rowCnt int
			for rows.Next() {
				if rowCnt > 0 {
					return errors.New(ctx, errors.MultipleRecords, op, "more than 1 job would have been updated")
				}
				rowCnt++
				err = r.ScanRows(ctx, rows, j)
				if err != nil {
					_ = rows.Close()
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to scan rows"))
				}
			}
			if err := rows.Err(); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get next row for job"))
			}
			if rowCnt == 0 {
				return errors.New(ctx, errors.RecordNotFound, op, fmt.Sprintf("job %q does not exist", name))
			}

			return nil
		},
	)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return j, nil
}

// LookupJob will look up a job in the repository using the job name. If the job is not
// found, it will return nil, nil.
//
// All options are ignored.
func (r *Repository) LookupJob(ctx context.Context, name string, _ ...Option) (*Job, error) {
	const op = "job.(Repository).LookupJob"
	if name == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing name")
	}

	j := allocJob()
	if err := r.reader.LookupWhere(ctx, j, "name = ?", []any{name}); err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil
		}
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for %v", name)))
	}
	return j, nil
}

// ListJobs returns a slice of Jobs.
//
// WithName and WithLimit are the only valid options.
func (r *Repository) ListJobs(ctx context.Context, opt ...Option) ([]*Job, error) {
	const op = "job.(Repository).ListJobs"
	opts := getOpts(opt...)
	limit := r.defaultLimit
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}
	var args []any
	var where []string
	if opts.withName != "" {
		where, args = append(where, "name = ?"), append(args, opts.withName)
	}

	var jobs []*Job
	err := r.reader.SearchWhere(ctx, &jobs, strings.Join(where, " and "), args, db.WithLimit(limit))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return jobs, nil
}

// deleteJob deletes the job for the provided job name from the repository
// returning a count of the number of records deleted.
//
// All options are ignored.
func (r *Repository) deleteJob(ctx context.Context, name string, _ ...Option) (int, error) {
	const op = "job.(Repository).deleteJob"
	if name == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing name")
	}

	var rowsDeleted int
	_, err := r.writer.DoTx(
		ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) (err error) {
			rowsDeleted, err = w.Exec(ctx, deleteJobByName, []any{name})
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			if rowsDeleted > 1 {
				return errors.New(ctx, errors.MultipleRecords, op, "more than 1 resource would have been deleted")
			}
			return nil
		},
	)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("delete failed for %v", name)))
	}

	return rowsDeleted, nil
}
