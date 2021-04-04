package job

const fetchWorkQuery = `
	select
	  private_id
	from
	  job j
	where
	  next_scheduled_run <= current_timestamp
	  and not exists (
		select
		from
		  job_run
		where
		  job_id = j.private_id
		  and status = 'running'
	  )
	order by
	  next_scheduled_run asc
	limit 1 
	for update
	skip locked;
`

const setNextScheduleRunQuery = `
	update
	  job
	set
	  next_scheduled_run = ?
	where
	  private_id = ?;
`

const endJobRunQuery = `
	update
	  job_run
	set
	  status = ?,
	  end_time = current_timestamp
	where
	  private_id = ?
	  and status = 'running';
`
