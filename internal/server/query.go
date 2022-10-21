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
	workerAuthRewrapQuery = `
		select distinct
			auth.worker_key_identifier,
			auth.controller_encryption_priv_key,
			auth.key_id
		from server_worker worker
			inner join worker_auth_authorized auth
				on auth.worker_id = worker.public_id
		where worker.scope_id = ?
			and auth.key_id = ?
	`
	workerAuthServerLedActivationTokenRewrapQuery = `
		select distinct
			auth_token.worker_id,
			auth_token.creation_time_encrypted,
			auth_token.key_id
		from server_worker worker
			inner join worker_auth_server_led_activation_token auth_token
				on auth_token.worker_id = worker.public_id
		where worker.scope_id = ?
			and auth_token.key_id = ?
	`
)
