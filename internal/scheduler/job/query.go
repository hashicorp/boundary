package job

const runJobsQuery = `
	insert into job_run (
	  job_plugin_id, job_name, server_id
	)
	select 
	  job_plugin_id, job_name, ?
	from job_jobs_to_run 
	order by next_scheduled_run asc
	limit ?
	returning *;
`

const createJobQuery = `
	insert into job (
	  plugin_id, -- $1
	  name, -- $2
	  description, -- $3
	  next_scheduled_run -- $4
	) values (
	  $1, -- plugin_id
	  $2, -- name
	  $3, -- description
	  wt_add_seconds_to_now($4) -- next_scheduled_run
	)
	returning *;
`

const setNextScheduledRunIfSoonerQuery = `
	update
	  job
	set
	  next_scheduled_run = least(wt_add_seconds_to_now(?), next_scheduled_run)
	where
	  plugin_id = ?
	  and name = ?
	returning *;
`

const setNextScheduledRunQuery = `
	update
	  job
	set
	  next_scheduled_run = wt_add_seconds_to_now(?)
	where
	  plugin_id = ?
	  and name = ?
	returning *;
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
	  completed_count = ?,
	  total_count     = ?,
	  status          = 'completed',
	  end_time        = current_timestamp
	where
	  private_id = ?
	  and status = 'running'
	returning *;
`

const failRunQuery = `
	update
	  job_run
	set
	  completed_count = ?,
	  total_count     = ?,
	  status          = 'failed',
	  end_time        = current_timestamp
	where
	  private_id = ?
	  and status = 'running'
	returning *;
`

const interruptRunsQuery = `
	update
	  job_run
	set 
	  status = 'interrupted',
	  end_time = current_timestamp
	where
	  update_time <= wt_add_seconds_to_now(?)
	  and status = 'running'
      %s
	returning *;
`
