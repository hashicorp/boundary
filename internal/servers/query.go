package servers

const (
	deleteWhereCreateTimeSql = `create_time < ?`
	deleteTagsByWorkerIdSql  = `
	delete 
	from server_worker_tag 
	where 
	  worker_id = ?`
)
