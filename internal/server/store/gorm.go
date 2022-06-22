package store

// TableName overrides the table name used by Controller to `server_controller`
func (Controller) TableName() string {
	return "server_controller"
}

// TableName overrides the table name used by WorkerTag to `worker_tag`
func (WorkerTag) TableName() string {
	return "server_worker_tag"
}
