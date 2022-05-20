package servers

const (
	deleteWhereCreateTimeSql = `create_time < ?`
	deleteTagsByWorkerIdSql  = `
	delete 
	from server_worker_tag 
	where 
	  	source = 'configuration'
	  and
		worker_id = ?`
)
