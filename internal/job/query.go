package job

const fetchWorkQuery = `
	SELECT
	  private_id
	FROM
	  job j
	WHERE
	  next_scheduled_run <= CURRENT_TIMESTAMP
	  AND NOT EXISTS (
		SELECT
		FROM
		  job_run
		WHERE
		  job_id = j.private_id
		  AND status = 'running'
	  )
	ORDER BY
	  next_scheduled_run ASC
	LIMIT 1 
	FOR UPDATE
	SKIP LOCKED;
`

const setNextScheduleRunQuery = `
	UPDATE
	  job
	SET
	  next_scheduled_run = ?
	WHERE
	  private_id = ?;
`

const endJobRunQuery = `
	UPDATE
	  job_run
	SET
	  status = ?,
	  end_time = CURRENT_TIMESTAMP
	WHERE
	  private_id = ?
	  AND status = 'running';
`
