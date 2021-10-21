package servers

const (
	deleteWhereCreateTimeSql = `create_time < ?`
	deleteTagsSql            = `server_id = ?`
)
