package plugin

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/scheduler"
	ua "go.uber.org/atomic"
)


const (
	orphanedHostCleanupJobName = "plugin_host_orpahend_hosts_cleanup"
	orphanedHostCleanupJobRunInterval = 1 * time.Hour
)

// OrphanedHostCleanupJob is the recurring job that syncs hosts from sets that are.
// The OrphanedHostCleanupJob is not thread safe,
// an attempt to Run the job concurrently will result in an JobAlreadyRunning error.
type OrphanedHostCleanupJob struct {
	reader  db.Reader
	writer  db.Writer
	kms     *kms.Kms
	limit   int

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
		reader:  r,
		writer:  w,
		kms:     kms,
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
func (r *OrphanedHostCleanupJob) Run(ctx context.Context) error {
	const op = "plugin.(OrphanedHostCleanupJob).Run"
	if !r.running.CAS(r.running.Load(), true) {
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
func (r *OrphanedHostCleanupJob) NextRunIn() (time.Duration, error) {
	const op = "plugin.(OrphanedHostCleanupJob).NextRunIn"
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