package scheduler

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
	jobRepo "github.com/hashicorp/boundary/internal/scheduler/job"
)

// Scheduler is used to register and run recurring jobs on the controller.
type Scheduler struct {
	serverId  string
	jobRepoFn jobRepo.JobRepoFactory

	runJobsLimit    uint
	runJobsInterval time.Duration
}

// New creates a new Scheduler
//
// • serverId must be provided and is the private id of the server that will run the scheduler
//
// • jobRepoFn must be provided and is a function that returns the job repository
//
// WithRunJobsLimit and WithRunJobsInterval are the only valid options.
func New(serverId string, jobRepoFn jobRepo.JobRepoFactory, opt ...Option) (*Scheduler, error) {
	const op = "scheduler.New"
	if serverId == "" {
		return nil, errors.New(errors.InvalidParameter, op, "missing server id")
	}
	if jobRepoFn == nil {
		return nil, errors.New(errors.InvalidParameter, op, "missing job repo function")
	}

	opts := getOpts(opt...)
	return &Scheduler{
		serverId:        serverId,
		jobRepoFn:       jobRepoFn,
		runJobsLimit:    opts.withRunJobsLimit,
		runJobsInterval: opts.withRunJobInterval,
	}, nil
}

// RegisterJob registers a job with the scheduler and persists the job into the repository.
//
// • job must be provided and is an implementer of the Job interface.
//
// • code must be provided and is used to uniquely distinguish between the same job implementation.
//
// The returned JobId is unique to the provide job and code.
// All options are ignored.
func (s *Scheduler) RegisterJob(ctx context.Context, job Job, code string, _ ...Option) (JobId, error) {
	panic("TODO (lruch): implement scheduler")
}

// UpdateJobNextRun sets the next scheduled run time for the provided jobId
// to the current database time incremented by the nextRunIn parameter.
//
// • jobId must be provided and is the id of the job returned by RegisterJob
//
// All options are ignored.
func (s *Scheduler) UpdateJobNextRun(ctx context.Context, jobId JobId, nextRunIn time.Duration, _ ...Option) error {
	panic("TODO (lruch): implement scheduler")
}

// Start begins the scheduling loop that will query the repository for jobs to run and
// run them in a goroutine.
func (s *Scheduler) Start() {
	panic("TODO (lruch): implement scheduler")
}

// Shutdown cancels all running jobs and stops scheduling new jobs.
func (s *Scheduler) Shutdown() {
	panic("TODO (lruch): implement scheduler")
}
