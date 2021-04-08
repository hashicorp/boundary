package job

const runJobsQuery = `
	with running_jobs as (
	  select job_id
		from job_run
	   where status = 'running'
	),
	jobs_to_run as (
	   select private_id as job_id
		 from job
		where next_scheduled_run <= current_timestamp
		  and private_id not in (select job_id from running_jobs)
		order by next_scheduled_run asc
	)
	insert into job_run (
      job_id, server_id
	)
	select 
	  job_id, ?
	from jobs_to_run 
	limit ?
	returning *;
`

const createJobQuery = `
	insert into job (
	  private_id, -- $1
	  name, -- $2
	  code, -- $3
	  description, -- $4
	  next_scheduled_run -- $5
	) values (
	  $1, -- private_id
	  $2, -- name
	  $3, -- code
	  $4, -- description
	  wt_add_seconds_to_now($5) -- next_scheduled_run
	)
	returning *;
`

const setNextScheduleRunQuery = `
	update
	  job
	set
	  next_scheduled_run = wt_add_seconds_to_now(?)
	where
	  private_id = ?;
`

const updateProgressQuery = `
	update
	  job_run
	set
	  completed_count = ?,
	  total_count = ?
	where
	  private_id = ?
	  and status = 'running'
	returning *;
`

const completeRunQuery = `
	update
	  job_run
	set
	  status = 'completed',
	  end_time = current_timestamp
	where
	  private_id = ?
	  and status = 'running'
	returning *;
`

const failRunQuery = `
	update
	  job_run
	set
	  status = 'failed',
	  end_time = current_timestamp
	where
	  private_id = ?
	  and status = 'running'
	returning *;
`
