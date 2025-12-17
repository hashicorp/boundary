// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package server

const (
	listWorkersQuery = `
	with connection_count (worker_id, count) as (
    select worker_id,
           count(1) as count
      from session_connection
     where closed_reason is null
  group by worker_id
  )
    select w.public_id,
           w.scope_id,
           w.description,
           w.name,
           w.address,
           w.create_time,
           w.update_time,
           w.version,
           w.last_status_time,
           w.type,
           w.release_version,
           w.operational_state,
           w.local_storage_state,
           cc.count as active_connection_count,
           wt.tags as api_tags,
           ct.tags as config_tags
      from server_worker w
 left join (   select worker_id, 
                     json_agg(json_build_object('key', key, 'value', value)) as tags 
                from server_worker_api_tag 
               group by worker_id) wt
        on w.public_id = wt.worker_id
 left join (   select worker_id, 
                     json_agg(json_build_object('key', key, 'value', value)) as tags 
                from server_worker_config_tag group by worker_id) ct
        on w.public_id = ct.worker_id
 left join connection_count as cc
        on w.public_id = cc.worker_id
    `

	lookupWorkerQuery = `
	with connection_count (worker_id, count) as (
    select worker_id,
           count(1) as count
      from session_connection
     where closed_reason is null
  group by worker_id
  )
    select w.public_id,
           w.scope_id,
           w.description,
           w.name,
           w.address,
           w.create_time,
           w.update_time,
           w.version,
           w.last_status_time,
           w.type,
           w.release_version,
           w.operational_state,
           w.local_storage_state,
           cc.count as active_connection_count,
           wt.tags as api_tags,
           ct.tags as config_tags
      from server_worker w
 left join (   select worker_id, 
                     json_agg(json_build_object('key', key, 'value', value)) as tags 
                from server_worker_api_tag 
               group by worker_id) wt
        on w.public_id = wt.worker_id
 left join (   select worker_id, 
                     json_agg(json_build_object('key', key, 'value', value)) as tags 
                from server_worker_config_tag group by worker_id) ct
        on w.public_id = ct.worker_id
 left join connection_count as cc
        on w.public_id = cc.worker_id
     where w.public_id = @worker_id
    `
	getStorageBucketCredentialStatesByWorkerId = `
		select spsb.public_id as storage_bucket_id,
			   wsbcs.permission_type, wsbcs.state, 
			   wsbcs.checked_at, wsbcs.error_details
		from worker_storage_bucket_credential_state wsbcs
			   join storage_plugin_storage_bucket spsb
				   on spsb.storage_bucket_credential_id = wsbcs.storage_bucket_credential_id
		where wsbcs.worker_id = @worker_id;
	`

	deleteWhereCreateTimeSql = `create_time < ?`

	deleteApiTagsByWorkerIdSql = `
	delete 
	  from server_worker_api_tag
	 where worker_id = ?
	`

	deleteConfigTagsByWorkerIdSql = `
	delete 
	  from server_worker_config_tag
	 where worker_id = ?
	`

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

	getWorkerAuthsByWorkerKeyIdQuery = `
		with key_id_to_worker_id as (
		    select worker_id 
     		  from worker_auth_authorized 
			 where worker_key_identifier = @worker_key_identifier
		)
		select * 
		  from worker_auth_authorized 
		 where worker_id in (select * 
 						       from key_id_to_worker_id)
	`

	getWorkerAuthStateByKeyIdQuery = `
		select state 
		  from worker_auth_authorized 
		 where worker_key_identifier = @worker_key_identifier
	`

	deleteWorkerAuthByKeyId = `
		with key_id_to_worker_id as (
			select worker_id 
			from worker_auth_authorized 
			where worker_key_identifier = @worker_key_identifier
		)
		delete 
			 from worker_auth_authorized 
			where state = 'current' and worker_id in (select * 
												        from key_id_to_worker_id)
	`

	updateWorkerAuthStateByKeyId = `
		update worker_auth_authorized 
		set state = 'current' 
		where worker_key_identifier = @worker_key_identifier
	`

	verifyKnownWorkersQuery = `
		select public_id 
		  from server_worker 
		 where public_id in (?);
	`

	getWorkerAuthsByWorkerIdQuery = `
		select * 
		  from worker_auth_authorized 
		where worker_id = @worker_id
	`

	authorizedWorkerQuery = `
		select distinct w.worker_key_identifier 
		from 
			worker_auth_certificate_bundle as w
		where
			w.worker_key_identifier in (?)
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

	listHcpbManagedWorkersQuery = `
        select w.public_id,
               w.address
          from server_worker            as w
     left join server_worker_config_tag as t
            on w.public_id = t.worker_id
         where last_status_time > now() - interval '%d seconds'
           and t.key   = 'boundary.cloud.hashicorp.com:managed'
           and t.value = 'true';
`

	listSelectSessionWorkers = `
        select w.public_id,
               w.name,
               w.address,
               w.release_version,
               w.local_storage_state,
               wt.tags as api_tags,
               ct.tags as config_tags
          from server_worker w
     left join (select worker_id, json_agg(json_build_object('key', key, 'value', value)) as tags from server_worker_api_tag group by worker_id) wt
            on w.public_id = wt.worker_id
     left join (select worker_id, json_agg(json_build_object('key', key, 'value', value)) as tags from server_worker_config_tag group by worker_id) ct
            on w.public_id = ct.worker_id
         where last_status_time > now() - interval '%d seconds'
           and operational_state = 'active';
`

	updateController = `
		update server_controller  
           set address     = @controller_address,  
               description = @controller_description,  
               update_time = now()  
         where private_id = @controller_private_id;  
`
)
