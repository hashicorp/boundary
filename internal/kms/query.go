package kms

const (
	// oldestPendingOrRunningRun lists the currently running or oldest
	// run that has not yet completed for the specified table name.
	oldestPendingOrRunningRun = `
select
	jr.key_id, jr.table_name, jr.total_count, jr.completed_count, jr.is_running
from
	kms_data_key_version_destruction_job_run jr
inner join
	kms_data_key_version_destruction_job     j
on
	jr.key_id = j.key_id
where
	jr.table_name=? and jr.completed_count!=jr.total_count
order by
	jr.is_running desc,
	j.create_time asc
limit
	1
`
	// updateCompletedCountQueryTemplate is used to update
	// the completed count for a specific table after running.
	// The interpolated variable is the table name.
	updateCompletedCountQueryTemplate = `
update kms_data_key_version_destruction_job_run
set
	is_running=false,
	completed_count=(
		total_count-(select count(*) from %q where key_id=@key_id)
	)
where
	key_id=@key_id and table_name=@table_name
`
)
