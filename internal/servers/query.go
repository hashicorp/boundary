package servers

const (
	deleteWhereCreateTimeSql = `create_time < ?`
	deleteConfigTagsSql      = `source = 'configuration' and worker_id = ?`
)
