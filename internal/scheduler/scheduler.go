package scheduler

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
	jobRepo "github.com/hashicorp/boundary/internal/scheduler/job"
	"github.com/hashicorp/go-hclog"
	ua "go.uber.org/atomic"
)

type runningJob struct {
	runId     string
	cancelCtx context.CancelFunc
}

// Scheduler is used to register and run recurring jobs on the controller.
type Scheduler struct {
	serverId  string
	jobRepoFn jobRepo.JobRepoFactory
	logger    hclog.Logger

	registeredJobs *sync.Map
	runningJobs    map[JobId]runningJob
	l              sync.RWMutex

	started         ua.Bool
	baseContext     context.Context
	baseCancel      context.CancelFunc
	runJobsLimit    uint
	runJobsInterval time.Duration
}

// New creates a new Scheduler
//
// • serverId must be provided and is the private id of the server that will run the scheduler
//
// • jobRepoFn must be provided and is a function that returns the job repository
//
// • logger must be provided and is used to log errors that occur during scheduling and running of jobs
//
// WithRunJobsLimit and WithRunJobsInterval are the only valid options.
func New(serverId string, jobRepoFn jobRepo.JobRepoFactory, logger hclog.Logger, opt ...Option) (*Scheduler, error) {
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
		serverId:        serverId,
		jobRepoFn:       jobRepoFn,
		logger:          logger,
		registeredJobs:  new(sync.Map),
		runningJobs:     make(map[JobId]runningJob),
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
	const op = "scheduler.(Scheduler).RegisterJob"
	if err := validateJob(job); err != nil {
		return "", errors.Wrap(err, op)
	}
	if code == "" {
		return "", errors.New(errors.InvalidParameter, op, "missing code")
	}

	repo, err := s.jobRepoFn()
	if err != nil {
		return "", errors.Wrap(err, op)
	}

	j, err := repo.CreateJob(ctx, job.Name(), code, job.Description())
	if err != nil {
		return "", errors.Wrap(err, op)
	}
	s.registeredJobs.Store(JobId(j.PrivateId), job)

	return JobId(j.PrivateId), nil
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
// run them in a goroutine.
func (s *Scheduler) Start() {
	if s.started.Load() {
		s.logger.Debug("scheduler already started, skipping")
		return
	}

	s.baseContext, s.baseCancel = context.WithCancel(context.Background())
	go s.start()
	// TODO (lruch): start go routine to monitor and update progress of running jobs
	// TODO (lruch): add watchdogs to monitor defunct jobs
	s.started.Store(true)
}

func (s *Scheduler) start() {
	s.logger.Debug("starting scheduling loop")
	timer := time.NewTimer(0)
	for {
		select {
		case <-s.baseContext.Done():
			s.logger.Debug("scheduling loop shutting down")
			return

		case <-timer.C:
			s.logger.Debug("waking up to run jobs")

			repo, err := s.jobRepoFn()
			if err != nil {
				s.logger.Error("error creating job repo", "error", err)
				break
			}

			runs, err := repo.RunJobs(s.baseContext, s.serverId, jobRepo.WithRunJobsLimit(s.runJobsLimit))
			if err != nil {
				s.logger.Error("error getting jobs to run from repo", "error", err)
				break
			}

			for _, r := range runs {
				err := s.runJob(r)
				if err != nil {
					s.logger.Error("error starting job", "error", err)
					if _, inner := repo.FailRun(s.baseContext, r.PrivateId); inner != nil {
						s.logger.Error("error updating failed job run", "error", inner)
					}
				}
			}
		}

		s.logger.Debug("scheduling loop going back to sleep")
		timer.Reset(s.runJobsInterval)
	}
}

func (s *Scheduler) runJob(r *jobRepo.Run) error {
	jobId := JobId(r.JobId)
	j, ok := s.registeredJobs.Load(jobId)
	job := j.(Job)
	s.logger.Debug(fmt.Sprintf("starting job run %q for job (%v: %v)", r.PrivateId, jobId, job.Name()))
	if !ok {
		return fmt.Errorf("job (%v: %v) not registered on scheduler", jobId, job.Name())
	}

	s.l.Lock()
	if _, ok := s.runningJobs[jobId]; ok {
		s.l.Unlock()
		return fmt.Errorf("job (%v: %v) is already running", jobId, job.Name())
	}
	jobContext, jobCancel := context.WithCancel(context.Background())
	s.runningJobs[jobId] = runningJob{runId: r.PrivateId, cancelCtx: jobCancel}
	s.l.Unlock()

	go func() {
		runErr := job.Run(jobContext)
		repo, err := s.jobRepoFn()
		if err != nil {
			// Failed to create repo needed update run.  Best option is to log error,
			// delete running job and return.
			s.logger.Error("error creating job repo after job run", "error", err)
			s.l.Lock()
			delete(s.runningJobs, jobId)
			s.l.Unlock()
			return
		}

		switch runErr {
		case nil:
			s.logger.Debug(fmt.Sprintf("job run %q for job (%v: %v) complete", r.PrivateId, jobId, job.Name()))
			if _, inner := repo.CompleteRun(jobContext, r.PrivateId, job.NextRunIn()); inner != nil {
				s.logger.Error("error updating completed job run", "error", inner)
			}
		default:
			s.logger.Debug(fmt.Sprintf("job run %q for job (%v: %v) failed: %v", r.PrivateId, jobId, job.Name(), runErr))
			if _, inner := repo.FailRun(jobContext, r.PrivateId); inner != nil {
				s.logger.Error("error updating failed job run", "error", inner)
			}
		}

		s.l.Lock()
		delete(s.runningJobs, jobId)
		s.l.Unlock()
	}()

	return nil
}

// Shutdown cancels all running jobs and stops scheduling new jobs.
func (s *Scheduler) Shutdown() {
	if !s.started.Load() {
		s.logger.Debug("scheduler already shut down, skipping")
		return
	}

	s.l.Lock()
	for jId, j := range s.runningJobs {
		j.cancelCtx()
		delete(s.runningJobs, jId)
	}
	s.l.Unlock()

	s.baseCancel()
	s.started.Store(false)
}
