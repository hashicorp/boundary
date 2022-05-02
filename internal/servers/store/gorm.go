package store

// TableName overrides the table name used by Worker to `server_worker`
func (Worker) TableName() string {
	return "server_worker"
}

// TableName overrides the table name used by Controller to `server_controller`
func (Controller) TableName() string {
	return "server_controller"
}
