package scheduler

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/scheduler/job"
	"github.com/hashicorp/go-hclog"
	ua "go.uber.org/atomic"
)

type jobRepoFactory func() (*job.Repository, error)

type runningJob struct {
	runId     string
	cancelCtx context.CancelFunc
	status    func() JobStatus
}

// Scheduler is used to register and run recurring jobs on the controller.
type Scheduler struct {
	serverId  string
	jobRepoFn jobRepoFactory
	logger    hclog.Logger

	registeredJobs *sync.Map
	runningJobs    *sync.Map
	started        ua.Bool

	runJobsLimit       uint
	runJobsInterval    time.Duration
	monitorInterval    time.Duration
	interruptThreshold time.Duration
}

// New creates a new Scheduler
//
// • serverId must be provided and is the private id of the server that will run the scheduler
//
// • jobRepoFn must be provided and is a function that returns the job repository
//
// • logger must be provided and is used to log errors that occur during scheduling and running of jobs
//
// WithRunJobsLimit, WithRunJobsInterval, WithMonitorInterval and WithInterruptThreshold are
// the only valid options.
func New(serverId string, jobRepoFn jobRepoFactory, logger hclog.Logger, opt ...Option) (*Scheduler, error) {
	const op = "scheduler.New"
	if serverId == "" {
		return nil, errors.New(errors.InvalidParameter, op, "missing server id")
	}
	if jobRepoFn == nil {
		return nil, errors.New(errors.InvalidParameter, op, "missing job repo function")
	}
	if logger == nil {
		return nil, errors.New(errors.InvalidParameter, op, "missing logger")
	}

	opts := getOpts(opt...)
	return &Scheduler{
		serverId:           serverId,
		jobRepoFn:          jobRepoFn,
		logger:             logger,
		registeredJobs:     new(sync.Map),
		runningJobs:        new(sync.Map),
		runJobsLimit:       opts.withRunJobsLimit,
		runJobsInterval:    opts.withRunJobInterval,
		monitorInterval:    opts.withMonitorInterval,
		interruptThreshold: opts.withInterruptThreshold,
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
func (s *Scheduler) RegisterJob(ctx context.Context, j Job, code string, _ ...Option) (JobId, error) {
	const op = "scheduler.(Scheduler).RegisterJob"
	if err := validateJob(j); err != nil {
		return "", errors.Wrap(err, op)
	}
	if code == "" {
		return "", errors.New(errors.InvalidParameter, op, "missing code")
	}

	jobId, err := job.NewJobId(j.Name(), code)
	if err != nil {
		return "", errors.Wrap(err, op)
	}

	if _, ok := s.registeredJobs.Load(jobId); ok {
		// Job already registered
		return JobId(jobId), nil
	}

	repo, err := s.jobRepoFn()
	if err != nil {
		return "", errors.Wrap(err, op)
	}

	_, err = repo.CreateJob(ctx, j.Name(), code, j.Description())
	if err != nil && !errors.IsUniqueError(err) {
		return "", errors.Wrap(err, op)
	}
	s.registeredJobs.Store(JobId(jobId), j)

	return JobId(jobId), nil
}

// UpdateJobNextRun sets the next scheduled run time for the provided jobId
// to the current database time incremented by the nextRunIn parameter.  If
// nextRunIn == 0 the job will be available to run immediately.
//
// • jobId must be provided and is the id of the job returned by RegisterJob
//
// All options are ignored.
func (s *Scheduler) UpdateJobNextRun(ctx context.Context, jobId JobId, nextRunIn time.Duration, _ ...Option) error {
	const op = "scheduler.(Scheduler).UpdateJobNextRun"
	if jobId == "" {
		return errors.New(errors.InvalidParameter, op, "missing job id")
	}
	repo, err := s.jobRepoFn()
	if err != nil {
		return errors.Wrap(err, op)
	}

	_, err = repo.UpdateJobNextRun(ctx, string(jobId), nextRunIn)
	if err != nil {
		return errors.Wrap(err, op)
	}
	return nil
}

// Start begins the scheduling loop that will query the repository for jobs to run and
// run them in a goroutine, the scheduler will stop all running jobs and stop requesting
// new jobs once the ctx past in is cancelled.
// The scheduler cannot be started again once the ctx is cancelled, a new scheduler will
// need to be instantiated in order to begin scheduling again.
func (s *Scheduler) Start(ctx context.Context) error {
	const op = "scheduler.(Scheduler).Start"
	if !s.started.CAS(s.started.Load(), true) {
		s.logger.Debug("scheduler already started, skipping")
		return nil
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	repo, err := s.jobRepoFn()
	if err != nil {
		return errors.Wrap(err, op)
	}

	// Interrupt all runs previously allocated to this server
	_, err = repo.InterruptRuns(ctx, 0, job.WithServerId(s.serverId))
	if err != nil {
		return errors.Wrap(err, op)
	}

	go s.start(ctx)
	go s.monitorJobs(ctx)

	return nil
}

func (s *Scheduler) start(ctx context.Context) {
	s.logger.Debug("starting scheduling loop")
	timer := time.NewTimer(0)
	for {
		select {
		case <-ctx.Done():
			s.logger.Debug("scheduling loop shutting down")
			return
		case <-timer.C:
			s.logger.Debug("waking up to run jobs")

			repo, err := s.jobRepoFn()
			if err != nil {
				s.logger.Error("error creating job repo", "error", err)
				break
			}

			runs, err := repo.RunJobs(ctx, s.serverId, job.WithRunJobsLimit(s.runJobsLimit))
			if err != nil {
				s.logger.Error("error getting jobs to run from repo", "error", err)
				break
			}

			for _, r := range runs {
				err := s.runJob(ctx, r)
				if err != nil {
					s.logger.Error("error starting job", "error", err)
					if _, inner := repo.FailRun(ctx, r.PrivateId); inner != nil {
						s.logger.Error("error updating failed job run", "error", inner)
					}
				}
			}
		}

		s.logger.Debug("scheduling loop going back to sleep")
		timer.Reset(s.runJobsInterval)
	}
}

func (s *Scheduler) runJob(ctx context.Context, r *job.Run) error {
	jobId := JobId(r.JobId)
	regJob, ok := s.registeredJobs.Load(jobId)
	if !ok {
		return fmt.Errorf("job %q not registered on scheduler", jobId)
	}
	j := regJob.(Job)
	s.logger.Debug("starting job run", "run id", r.PrivateId, "job id", jobId, "name", j.Name())

	repo, err := s.jobRepoFn()
	if err != nil {
		return fmt.Errorf("failed to create job repository: %w", err)
	}

	jobContext, jobCancel := context.WithCancel(ctx)
	_, loaded := s.runningJobs.LoadOrStore(jobId, runningJob{runId: r.PrivateId, cancelCtx: jobCancel, status: j.Status})
	if loaded {
		jobCancel()
		return fmt.Errorf("job (%v: %v) is already running", jobId, j.Name())
	}

	go func() {
		defer jobCancel()
		runErr := j.Run(jobContext)
		switch runErr {
		case nil:
			s.logger.Debug("job run complete", "run id", r.PrivateId, "job id", jobId, "name", j.Name())
			if _, inner := repo.CompleteRun(jobContext, r.PrivateId, j.NextRunIn()); inner != nil {
				s.logger.Error("error updating completed job run", "error", inner)
			}
		default:
			s.logger.Debug("job run failed", "run id", r.PrivateId, "job id", jobId, "name", j.Name())
			if _, inner := repo.FailRun(jobContext, r.PrivateId); inner != nil {
				s.logger.Error("error updating failed job run", "error", inner)
			}
		}

		s.runningJobs.Delete(jobId)
	}()

	return nil
}

func (s *Scheduler) monitorJobs(ctx context.Context) {
	s.logger.Debug("starting job monitor loop")
	timer := time.NewTimer(0)
	for {
		select {
		case <-ctx.Done():
			s.logger.Debug("job monitor loop shutting down")
			return

		case <-timer.C:
			// Update progress of all running jobs
			s.runningJobs.Range(func(_, v interface{}) bool {
				err := s.updateRunningJobProgress(ctx, v.(runningJob))
				if err != nil {
					s.logger.Error("error updating job progress", "error", err)
				}
				return true
			})

			// Check for defunct runs to interrupt
			repo, err := s.jobRepoFn()
			if err != nil {
				s.logger.Error("error creating job repo", "error", err)
				break
			}

			_, err = repo.InterruptRuns(ctx, s.interruptThreshold)
			if err != nil {
				s.logger.Error("error interrupting job runs", "error", err)
			}
		}
		timer.Reset(s.monitorInterval)
	}
}

func (s *Scheduler) updateRunningJobProgress(ctx context.Context, j runningJob) error {
	repo, err := s.jobRepoFn()
	if err != nil {
		return fmt.Errorf("error creating job repo %w", err)
	}
	status := j.status()
	_, err = repo.UpdateProgress(ctx, j.runId, status.Completed, status.Total)
	if errors.Match(errors.T(errors.InvalidJobRunState), err) {
		// Job has been persisted with a final run status, cancel job context to trigger early exit.
		j.cancelCtx()
		return nil
	}
	if err != nil {
		return err
	}

	return nil
}
