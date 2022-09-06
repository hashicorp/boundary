// Package job provides a Job and a Run struct suitable for persisting to
// the repository.
//
// A Job represents work that should be run at a predetermined time and needs to be synchronized
// across servers to ensure that one and only one instance of a job is running at any given time.
// The job's name must be unique to the plugin that registered the job, the (plugin_id, name)
// uniqueness is enforced by the database.
//
// A Run represents a single execution of a job, only a single run can be in a
// running state for a specific job.  The private_id (primary key) is generated by the
// repository during RunJobs.
//
// # Repository
//
// A repository provides methods for creating, updating, retrieving, and
// deleting Jobs. It also provides methods to run jobs, update progress of runs
// and complete, fail or interrupt runs.
// A new repository should be created for each transaction. For example:
//
//	var wrapper wrapping.Wrapper
//	... init wrapper ...
//
//	// db implements both the reader and writer interfaces.
//	db, _ := db.Open(db.Postgres, url)
//
//	var repo *job.Repository
//	repo, _ = job.NewRepository(db, db, wrapper)
//
//	var j *job.Job
//	j, _ = repo.UpsertJob(context.Background(), j, "name", "description")
//
//	var runs []*Run
//	repo, _ = job.NewRepository(db, db, wrapper)
//	runs, _ = repo.RunJobs(context.Background(), "serverId")
//
//	... run job ...
//
//	var run *Run
//	repo, _ = job.NewRepository(db, db, wrapper)
//	run, _ = repo.UpdateProgress(ctx, run, []string{"TotalCount", "CompletedCount"})
//
//	nextJobRun = time.Now().Add(time.Hour)
//
//	repo, _ = job.NewRepository(db, db, wrapper)
//	run, _ = repo.CompleteRun(ctx, run.PrivateId, job.Completed, nextJobRun)
package job
