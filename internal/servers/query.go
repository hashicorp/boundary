package servers

const (
	deleteWhereCreateTimeSql = `create_time < ?`
	deleteTagsSql            = `worker_id = ?`
)
