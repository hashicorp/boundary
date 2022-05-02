package servers

// TableName overrides the table name used by WorkerTag to `worker_tag`
func (WorkerTag) TableName() string {
	return "server_worker_tag"
}
