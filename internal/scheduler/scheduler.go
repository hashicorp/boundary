package scheduler

import (
	"context"
	"time"

	jobRepo "github.com/hashicorp/boundary/internal/scheduler/job"
)

// Scheduler TODO (lruch): add doc
type Scheduler struct {
	serverId  string
	jobRepoFn jobRepo.JobRepoFactory
}

// New TODO (lruch): add doc
func New(serverId string, jobRepoFn jobRepo.JobRepoFactory) *Scheduler {
	return &Scheduler{
		serverId:  serverId,
		jobRepoFn: jobRepoFn,
	}
}

// RegisterJob TODO (lruch): add doc
func (s *Scheduler) RegisterJob(ctx context.Context, job Job, code string) (JobId, error) {
	panic("TODO (lruch): implement scheduler")
}

// UpdateJobNextRun TODO (lruch): add doc
func (s *Scheduler) UpdateJobNextRun(ctx context.Context, jobId JobId, nextRunIn time.Duration) error {
	panic("TODO (lruch): implement scheduler")
}

// Start TODO (lruch): add doc
func (s *Scheduler) Start() {
	panic("TODO (lruch): implement scheduler")
}

// Shutdown TODO (lruch): add doc
func (s *Scheduler) Shutdown() {
	panic("TODO (lruch): implement scheduler")
}
