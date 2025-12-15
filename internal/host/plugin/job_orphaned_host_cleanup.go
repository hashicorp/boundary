// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/scheduler"
	ua "go.uber.org/atomic"
)

const (
	orphanedHostCleanupJobName        = "plugin_host_orpahend_hosts_cleanup"
	orphanedHostCleanupJobRunInterval = 5 * time.Minute
)

// OrphanedHostCleanupJob is the recurring job that syncs hosts from sets that are.
// The OrphanedHostCleanupJob is not thread safe,
// an attempt to Run the job concurrently will result in an JobAlreadyRunning error.
type OrphanedHostCleanupJob struct {
	reader db.Reader
	writer db.Writer
	kms    *kms.Kms
	limit  int

	running      ua.Bool
	numHosts     int
	numProcessed int
}

// newOrphanedHostCleanupJob creates a new in-memory OrphanedHostCleanupJob.
func newOrphanedHostCleanupJob(ctx context.Context, r db.Reader, w db.Writer, kms *kms.Kms, _ ...Option) (*OrphanedHostCleanupJob, error) {
	const op = "plugin.newOrphanedHostCleanupJob"
	switch {
	case r == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing db.Reader")
	case w == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing db.Writer")
	case kms == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing kms")
	}

	return &OrphanedHostCleanupJob{
		reader: r,
		writer: w,
		kms:    kms,
	}, nil
}

// Status returns the current status of the set sync job.  Total is the total number
// of sets that are to be synced. Completed is the number of sets already synced.
func (r *OrphanedHostCleanupJob) Status() scheduler.JobStatus {
	return scheduler.JobStatus{
		Completed: r.numProcessed,
		Total:     r.numHosts,
	}
}

// Run queries the plugin host repo hosts with no memberships, it then
// deletes those hosts.  Can not be run in parallel, if
// Run is invoked while already running an error with code JobAlreadyRunning
// will be returned.
func (r *OrphanedHostCleanupJob) Run(ctx context.Context, _ time.Duration) error {
	const op = "plugin.(OrphanedHostCleanupJob).Run"
	if !r.running.CompareAndSwap(r.running.Load(), true) {
		return errors.New(ctx, errors.JobAlreadyRunning, op, "job already running")
	}
	defer r.running.Store(false)

	// Verify context is not done before running
	if err := ctx.Err(); err != nil {
		return errors.Wrap(ctx, err, op)
	}

	i, err := r.deleteOrphanedHosts(ctx)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	// Set numProcessed and numHosts for status report
	r.numProcessed, r.numHosts = i, i
	return nil
}

// NextRunIn returns the default run frequency of the cleanup job.
func (r *OrphanedHostCleanupJob) NextRunIn(_ context.Context) (time.Duration, error) {
	return orphanedHostCleanupJobRunInterval, nil
}

// Name is the unique name of the job.
func (r *OrphanedHostCleanupJob) Name() string {
	return orphanedHostCleanupJobName
}

// Description is the human readable description of the job.
func (r *OrphanedHostCleanupJob) Description() string {
	return "Periodically deletes plugin based hosts which are not members of any sets."
}

// deleteOrphanedHosts deletes any hosts that no longer belong to any set.
// WithLimit is the only option supported. No options are currently supported.
func (r *OrphanedHostCleanupJob) deleteOrphanedHosts(ctx context.Context, _ ...Option) (int, error) {
	const op = "plugin.(OrphanedHostCleanupJob).deleteOrphanedHosts"

	query := `
public_id in
	(select public_id
		from host_plugin_host
		where public_id not in
			(select host_id from host_plugin_set_member))
`

	var hostAggs []*hostAgg
	err := r.reader.SearchWhere(ctx, &hostAggs, query, nil)
	switch {
	case err != nil:
		return db.NoRowsAffected, errors.Wrap(ctx, err, op)
	case len(hostAggs) == 0:
		return db.NoRowsAffected, nil
	}

	projectToHost := make(map[string][]*Host)
	for _, ha := range hostAggs {
		h := allocHost()
		h.PublicId = ha.PublicId
		projectToHost[ha.ProjectId] = append(projectToHost[ha.ProjectId], h)
	}

	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			for projectId, hosts := range projectToHost {
				oplogWrapper, err := r.kms.GetWrapper(ctx, projectId, kms.KeyPurposeOplog)
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
				}
				for _, h := range hosts {
					metadata := h.oplog(oplog.OpType_OP_TYPE_DELETE)
					dHost := h.clone()
					if _, err := w.Delete(ctx, dHost, db.WithOplog(oplogWrapper, metadata)); err != nil {
						return errors.Wrap(ctx, err, op)
					}
				}
			}
			return nil
		})
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}

	return len(hostAggs), nil
}
