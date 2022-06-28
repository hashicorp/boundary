package server

const (
	deleteWhereCreateTimeSql = `create_time < ?`

	deleteTagsByWorkerIdSql = `
	delete 
	from server_worker_tag 
	where 
		source = ?
	and
		worker_id = ?`

	deleteWorkerAuthQuery = `
		delete from worker_auth_authorized
 		where worker_key_identifier = @worker_key_identifier;
	`
	deleteWorkerCertBundlesQuery = `
		delete from worker_auth_certificate_bundle
 		where worker_key_identifier = @worker_key_identifier;
	`
	deleteRootCertificateQuery = `
		delete from worker_auth_ca_certificate
 		where state = @state;
	`
)
