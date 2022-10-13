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
	jr.key_id=j.key_id
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
	// dataKeyVersionIdScopeIdQuery looks up the scopeId
	// a specific data key version is in.
	dataKeyVersionIdScopeIdQuery = `
select
	rk.scope_id
from
	kms_root_key         rk
inner join
	kms_data_key         dk
on
	dk.root_key_id=rk.private_id
inner join
	kms_data_key_version dkv
on
	dkv.data_key_id=dk.private_id
where
	dkv.private_id=?
`
	// finishedDestructionJobsQuery returns all key version
	// destruction jobs that have completed rewrapping all of their rows.
	finishedDestructionJobsQuery = `
select
	j.key_id
from
	kms_data_key_version_destruction_job     j
inner join
	kms_data_key_version_destruction_job_run jr
on
	j.key_id=jr.key_id
group by
	(j.key_id)
having
	sum(jr.total_count)=sum(jr.completed_count)
`
	// findAffectedRowsForKeyQueryTemplate is used to find rows encrypted
	// with a specific data key version ID in a table. The interpolated
	// variable is the table name.
	findAffectedRowsForKeyQueryTemplate = `select count(*) from %q where key_id=?`
)
