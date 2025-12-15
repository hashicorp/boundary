// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package scheduler

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/boundary/internal/scheduler/job"
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

	registeredJobs *sync.Map
	runningJobs    *sync.Map
	started        ua.Bool

	runJobsInterval    time.Duration
	monitorInterval    time.Duration
	interruptThreshold time.Duration
	runNow             chan struct{}
}

// New creates a new Scheduler
//
// • serverId must be provided and is the private id of the server that will run the scheduler
//
// • jobRepoFn must be provided and is a function that returns the job repository
//
// WithRunJobsInterval, WithMonitorInterval and WithInterruptThreshold are
// the only valid options.
func New(ctx context.Context, serverId string, jobRepoFn jobRepoFactory, opt ...Option) (*Scheduler, error) {
	const op = "scheduler.New"
	if serverId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing server id")
	}
	if jobRepoFn == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing job repo function")
	}

	opts := getOpts(opt...)
	return &Scheduler{
		serverId:           serverId,
		jobRepoFn:          jobRepoFn,
		registeredJobs:     new(sync.Map),
		runningJobs:        new(sync.Map),
		runJobsInterval:    opts.withRunJobInterval,
		monitorInterval:    opts.withMonitorInterval,
		interruptThreshold: opts.withInterruptThreshold,
		runNow:             make(chan struct{}, 1),
	}, nil
}

// RegisterJob registers a job with the scheduler and persists the job into the repository.
//
// • job must be provided and is an implementer of the Job interface.
//
// WithNextRunIn is the only valid options.
func (s *Scheduler) RegisterJob(ctx context.Context, j Job, opt ...Option) error {
	const op = "scheduler.(Scheduler).RegisterJob"
	if err := validateJob(ctx, j); err != nil {
		return errors.Wrap(ctx, err, op)
	}

	if _, ok := s.registeredJobs.Load(j.Name()); ok {
		// Job already registered
		return nil
	}

	repo, err := s.jobRepoFn()
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	opts := getOpts(opt...)
	_, err = repo.UpsertJob(ctx, j.Name(), j.Description(), job.WithNextRunIn(opts.withNextRunIn))
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	s.registeredJobs.Store(j.Name(), j)

	return nil
}

// UpdateJobNextRunInAtLeast updates the next scheduled run time for the provided name,
// setting the job's NextScheduledRun time to either the current database time incremented by
// the nextRunInAtLeast parameter or the current NextScheduledRun time value, which ever is sooner.
// If nextRunInAtLeast == 0 the job will be available to run immediately.
//
// WithRunNow is the only supported option.
func (s *Scheduler) UpdateJobNextRunInAtLeast(ctx context.Context, name string, nextRunInAtLeast time.Duration, opt ...Option) error {
	const op = "scheduler.(Scheduler).UpdateJobNextRunInAtLeast"
	if name == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing name")
	}
	repo, err := s.jobRepoFn()
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	_, err = repo.UpdateJobNextRunInAtLeast(ctx, name, nextRunInAtLeast)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	opts := getOpts(opt...)
	if opts.withRunNow {
		s.RunNow()
	}
	return nil
}

// Start begins the scheduling loop that will query the repository for jobs to run and
// run them in a goroutine, the scheduler will stop all running jobs and stop requesting
// new jobs once the ctx past in is canceled.
// The scheduler cannot be started again once the ctx is canceled, a new scheduler will
// need to be instantiated in order to begin scheduling again.
func (s *Scheduler) Start(ctx context.Context, wg *sync.WaitGroup) error {
	const op = "scheduler.(Scheduler).Start"
	if !s.started.CompareAndSwap(s.started.Load(), true) {
		event.WriteSysEvent(ctx, op, "scheduler already started, skipping")
		return nil
	}
	if ctx == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing context")
	}
	if wg == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing wait group")
	}

	if err := ctx.Err(); err != nil {
		return errors.Wrap(ctx, err, op)
	}

	repo, err := s.jobRepoFn()
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	// Interrupt all runs previously allocated to this server
	_, err = repo.InterruptRuns(ctx, 0, job.WithControllerId(s.serverId))
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	wg.Add(2)
	go func() {
		defer wg.Done()
		s.start(ctx)
	}()
	go func() {
		defer wg.Done()
		s.monitorJobs(ctx)
	}()

	return nil
}

// RunNow attempts to trigger the scheduling loop, if the scheduling loop is actively running it will
// cause the loop to run again immediately after finishing.
func (s *Scheduler) RunNow() {
	// Do not block on writing to runNow chan.
	select {
	case s.runNow <- struct{}{}:
	default:
	}
}

func (s *Scheduler) start(ctx context.Context) {
	const op = "scheduler.(Scheduler).start"
	event.WriteSysEvent(ctx, op, "scheduling loop running",
		"server id", s.serverId,
		"run interval", s.runJobsInterval.String(),
	)
	timer := time.NewTimer(0)
	var wg sync.WaitGroup
	for {
		select {
		case <-ctx.Done():
			event.WriteSysEvent(ctx, op, "scheduling loop received shutdown, waiting for jobs to finish",
				"server id", s.serverId)
			wg.Wait()
			event.WriteSysEvent(ctx, op, "scheduling loop shutting down", "server id", s.serverId)
			return
		case <-timer.C:
		case <-s.runNow:
		}

		s.schedule(ctx, &wg)
		timer.Reset(s.runJobsInterval)
	}
}

func (s *Scheduler) schedule(ctx context.Context, wg *sync.WaitGroup) {
	const op = "scheduler.(Scheduler).schedule"
	repo, err := s.jobRepoFn()
	if err != nil {
		event.WriteError(ctx, op, err, event.WithInfoMsg("error creating job repo"))
		return
	}

	runs, err := repo.RunJobs(ctx, s.serverId)
	if err != nil {
		event.WriteError(ctx, op, err, event.WithInfoMsg("error getting jobs to run from repo"))
		return
	}

	for _, r := range runs {
		err := s.runJob(ctx, wg, r)
		if err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("error starting job"))
			if _, inner := repo.FailRun(ctx, r.PrivateId, 0, 0, 0); inner != nil {
				event.WriteError(ctx, op, inner, event.WithInfoMsg("error updating failed job run"))
			}
		}
	}
}

func (s *Scheduler) runJob(ctx context.Context, wg *sync.WaitGroup, r *job.Run) error {
	const op = "scheduler.(Scheduler).runJob"
	regJob, ok := s.registeredJobs.Load(r.JobName)
	if !ok {
		return fmt.Errorf("job %q not registered on scheduler", r.JobName)
	}

	repo, err := s.jobRepoFn()
	if err != nil {
		return fmt.Errorf("failed to create job repository: %w", err)
	}

	j := regJob.(Job)
	rj := &runningJob{runId: r.PrivateId, status: j.Status}
	_, loaded := s.runningJobs.LoadOrStore(r.JobName, rj)
	if loaded {
		return fmt.Errorf("job %q is already running", r.JobName)
	}
	var jobContext context.Context
	jobContext, rj.cancelCtx = context.WithCancel(ctx)

	wg.Add(1)
	go func() {
		defer rj.cancelCtx()
		defer wg.Done()
		runErr := j.Run(jobContext, s.interruptThreshold)

		var updateErr error
		switch {
		case ctx.Err() != nil:
			// Base context is no longer valid, skip repo updates as they will fail and exit
		case runErr == nil:
			nextRun, inner := j.NextRunIn(ctx)
			if inner != nil {
				event.WriteError(ctx, op, inner, event.WithInfoMsg("error getting next run time", "name", j.Name()))
			}
			updateErr = repo.CompleteRun(ctx, r.PrivateId, nextRun)
		default:
			event.WriteError(ctx, op, runErr, event.WithInfoMsg("job run failed", "run id", r.PrivateId, "name", j.Name()))

			status := j.Status() // Get final status report to update run progress with
			_, updateErr = repo.FailRun(ctx, r.PrivateId, status.Completed, status.Total, status.Retries)
		}

		if updateErr != nil {
			event.WriteError(ctx, op, updateErr, event.WithInfoMsg("error updating job run", "name", j.Name()))
		}
		s.runningJobs.Delete(j.Name())
	}()

	return nil
}

func (s *Scheduler) monitorJobs(ctx context.Context) {
	const op = "scheduler.(Scheduler).monitorJobs"
	event.WriteSysEvent(ctx, op, "monitor loop running",
		"server id", s.serverId,
		"monitor interval", s.monitorInterval.String(),
		"interrupt threshold", s.interruptThreshold.String())
	timer := time.NewTimer(0)
	for {
		select {
		case <-ctx.Done():
			event.WriteSysEvent(ctx, op, "job monitor loop shutting down")
			return

		case <-timer.C:
			// Update progress of all running jobs
			s.runningJobs.Range(func(_, v any) bool {
				err := s.updateRunningJobProgress(ctx, v.(*runningJob))
				if err != nil {
					event.WriteError(ctx, op, err, event.WithInfoMsg("error updating job progress"))
				}
				return true
			})

			// Check for defunct runs to interrupt
			repo, err := s.jobRepoFn()
			if err != nil {
				event.WriteError(ctx, op, err, event.WithInfoMsg("error creating job repo"))
				break
			}

			_, err = repo.InterruptRuns(ctx, s.interruptThreshold)
			if err != nil {
				event.WriteError(ctx, op, err, event.WithInfoMsg("error interrupting job runs"))
			}
		}
		timer.Reset(s.monitorInterval)
	}
}

func (s *Scheduler) updateRunningJobProgress(ctx context.Context, j *runningJob) error {
	repo, err := s.jobRepoFn()
	if err != nil {
		return fmt.Errorf("error creating job repo %w", err)
	}
	status := j.status()
	_, err = repo.UpdateProgress(ctx, j.runId, status.Completed, status.Total, status.Retries)
	if errors.Match(errors.T(errors.InvalidJobRunState), err) || errors.IsNotFoundError(err) {
		// Job has been persisted with a final run status or deleted, cancel job context to trigger early exit.
		j.cancelCtx()
		return nil
	}
	if err != nil {
		return err
	}

	return nil
}

// GetRunJobsInterval returns the value runJobsInterval,
// which represents an interval at which the scheduler
// will query the repository for jobs to run.
func (s *Scheduler) GetRunJobsInterval() time.Duration {
	return s.runJobsInterval
}
