// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package session

import (
	"fmt"
	"strings"
)

const (
	activateStateCte = `
insert into session_state
with not_active as (
	select session_id, 'active' as state
	from
		session s,
		session_state ss
	where
		s.public_id = ss.session_id and
		ss.state = 'pending' and
		ss.session_id = @session_id and
		s.version = @version and
		s.public_id not in(select session_id from session_state where session_id = @session_id and state = 'active')
)
select * from not_active;
`

	// updateSessionState checks that we don't already have a row for the new
	// state or it's not already terminated (final state) before inserting a new
	// state.
	updateSessionState = `
insert into session_state(session_id, state)
select
	@session_id, @status
from
	session s
where
	s.public_id = @session_id and
	s.public_id not in (
		select
			session_id
		from
			session_state
		where
			-- already in the updated state
			(
				session_id = @session_id and
				state = @status
			) or
			-- already terminated
			session_id in (
				select
					session_id
				from
					session_state
				where
					session_id = @session_id and
					state = 'terminated'
			)
	);
`
	authorizeConnectionCte = `
with connections_available as (
	select
		s.public_id
 	from
		session s
	where
		s.public_id = @session_id and
 		(s.connection_limit = -1 or
		s.connection_limit > (select count(*) from session_connection sc where sc.session_id = @session_id ))
),
unexpired_session as (
	select
		s.public_id
	from
		session s
	where
		s.public_id in (select * from  connections_available) and
		s.expiration_time > now()
),
active_session as (
	select
		ss.session_id as session_id,
		@public_id as public_id,
		@worker_id as worker_id
	from
		session_state ss
	where
		ss.session_id in (select * from unexpired_session) and
		ss.state = 'active' and
		upper(ss.active_time_range) is null
)
insert into session_connection (
  	session_id,
 	public_id,
	worker_id
)
select * from active_session;
`
	remainingConnectionsCte = `
with
session_connection_count(current_connection_count) as (
	select count(*)
	from
		session_connection sc
	where
		sc.session_id = @session_id
),
session_connection_limit(expiration_time, connection_limit) as (
	select
		s.expiration_time,
		s.connection_limit,
		s.egress_worker_filter,
		s.ingress_worker_filter
	from
		session s
	where
		s.public_id = @session_id
)
select expiration_time, connection_limit, egress_worker_filter, ingress_worker_filter, current_connection_count
from
	session_connection_limit, session_connection_count;
`

	// connectConnection sets the connected time range to (now, infinity) to
	// indicate the connection is connected.
	connectConnection = `
     update session_connection 
        set connected_time_range=tstzrange(now(),'infinity') 
      where public_id=@public_id
`

	terminateSessionIfPossible = `
    -- is terminate_session_id in a canceling state
    with session_version as (
		select 
			version
		from 
			session
		where public_id = @public_id
	),
    canceling_session(session_id) as
    (
      select 
        session_id
      from
        session_state ss
      where 
        ss.session_id = @public_id and
        ss.state = 'canceling' and 
        upper(ss.active_time_range) is null
    )
    update session us
      set version = version +1,
	  termination_reason = 
      case 
        -- timed out sessions
        when now() > us.expiration_time then 'timed out'
        -- canceling sessions
        when us.public_id in(
          select 
            session_id 
          from 
            canceling_session cs 
          where
            us.public_id = cs.session_id
          ) then 'canceled' 
        -- default: session connection limit reached.
        else 'connection limit'
      end
    where
      -- limit update to just the terminating_session_id
      us.public_id = @public_id and
  	  us.version = (select * from session_version) and
      termination_reason is null and
      -- session expired or connection limit reached
      (
        -- expired sessions...
        now() > us.expiration_time or 
        -- connection limit reached...
        (
          -- handle unlimited connections...
          connection_limit != -1 and
          (
            select count (*) 
              from session_connection sc 
            where 
              sc.session_id = us.public_id
          ) >= connection_limit
        ) or 
        -- canceled sessions
        us.public_id in (
          select 
            session_id
          from
            canceling_session cs
          where 
            us.public_id = cs.session_id 
        )
      ) and 
      -- make sure there are no existing connections
      us.public_id not in (
        select 
          session_id 
        from 
          session_connection
        where 
          upper(connected_time_range) > now() or 
          connected_time_range is null
      )
`

	// termSessionUpdate is one stmt that terminates sessions for the following
	// reasons:
	//	* sessions that are expired and all their connections are closed.
	// 	* sessions that are canceling and all their connections are closed
	//  * sessions that have exhausted their connection limit and all their connections are closed.
	termSessionsUpdate = `
with canceling_session(session_id) as
(
	select
		session_id
	from
		session_state ss
	where
		ss.state = 'canceling' and
		upper(ss.active_time_range) is null
)
update session us
	set termination_reason =
	case
		-- timed out sessions
		when now() > us.expiration_time then 'timed out'
		-- canceling sessions
		when us.public_id in(
			select
				session_id
			from
				canceling_session cs
			where
				us.public_id = cs.session_id
			) then 'canceled'
		-- default: session connection limit reached.
		else 'connection limit'
	end
where
	termination_reason is null and
	-- session expired or connection limit reached
	(
		-- expired sessions...
		now() > us.expiration_time or
		-- connection limit reached...
		(
			-- handle unlimited connections...
			connection_limit != -1 and
			(
			select count (*)
				from session_connection sc
			where
				sc.session_id = us.public_id
			) >= connection_limit
		) or
		-- canceled sessions
		us.public_id in (
			select
				session_id
			from
				canceling_session cs
			where
				us.public_id = cs.session_id
		)
	) and
	-- make sure there are no existing connections
    us.public_id not in (
      select session_id
        from session_connection
       where upper(connected_time_range) > now()
          or connected_time_range is null
    );
`

	// closeConnectionsForDeadServersCte finds connections that are:
	//
	// * not closed
	// * belong to servers that have not reported in within an acceptable
	// threshold of time
	// * belong to servers where we do not know when they last reported.
	//
	// and marks them as closed.
	//
	// The query returns the set of servers that have had connections closed
	// along with their last update time and the number of connections closed on
	// each. If the worker has not yet sent a session info update, we use the
	// worker's last update time as the last update time.
	closeConnectionsForDeadServersCte = `
   with
   dead_workers (worker_id, last_update_time) as (
         select w.public_id as worker_id,
                coalesce(wsi.last_request_time, w.update_time) as last_update_time
           from server_worker w
      left join server_worker_session_info_request wsi on wsi.worker_id = w.public_id 
          where wsi.last_request_time < wt_sub_seconds_from_now(@grace_period_seconds)
             or (    wsi.last_request_time is null
                 and w.update_time < wt_sub_seconds_from_now(@grace_period_seconds))
   ),
   closed_connections (connection_id, worker_id) as (
         update session_connection
            set closed_reason = 'system error'
          where worker_id in (select worker_id from dead_workers)
            and closed_reason is null
      returning public_id, worker_id
   )
   select closed_connections.worker_id,
          dead_workers.last_update_time as last_update_time,
          count(closed_connections.connection_id) as number_connections_closed
     from closed_connections
     join dead_workers
       on closed_connections.worker_id = dead_workers.worker_id
 group by closed_connections.worker_id, dead_workers.last_update_time
 order by closed_connections.worker_id;
`

	// closeWorkerlessConnections closes any open connections which has the
	// worker id set to null.
	closeWorkerlessConnections = `
	update session_connection
		set closed_reason = 'system error'
	where worker_id is null
		and closed_reason is null
	returning public_id;
`
	closeOrphanedConnections = `
update session_connection
   set closed_reason = 'system error'
 where worker_id = @worker_id
   and update_time < wt_sub_seconds_from_now(@worker_state_delay_seconds)
   and (
        connected_time_range is null
        or
        upper(connected_time_range) > now() 
       )
   %s
returning public_id;
`
	sessionCredentialRewrapQuery = `
select distinct
  cred.session_id,
  cred.key_id,
  cred.credential,
  cred.credential_sha256
from session
  inner join session_credential cred
    on cred.session_id = session.public_id
where session.project_id = ?
  and cred.key_id = ?
`
	sessionCredentialRewrapUpdate = `
update session_credential
	set credential = ?,
		key_id = ?
where session_id = ?
	and credential_sha256 = ?;
`
	listSessionsTemplate = `
with session_ids as (
    select public_id
      from session
     where %s -- search condition for applying permissions is constructed
  order by create_time desc, public_id desc
     limit %d
)
   select *
     from session_list
    where session_list.public_id in (select * from session_ids)
 order by create_time desc, public_id desc;
`
	listSessionsPageTemplate = `
with session_ids as (
    select public_id
      from session
     where (create_time, public_id) < (@last_item_create_time, @last_item_id)
       and %s -- search condition for applying permissions is constructed
  order by create_time desc, public_id desc
     limit %d
)
   select *
     from session_list
    where session_list.public_id in (select * from session_ids)
 order by create_time desc, public_id desc;
`
	refreshSessionsTemplate = `
with session_ids as (
    select public_id
      from session
     where update_time > @updated_after_time
       and %s -- search condition for applying permissions is constructed
  order by update_time desc, public_id desc
     limit %d
)
  select *
    from session_list
   where session_list.public_id in (select * from session_ids)
order by update_time desc, public_id desc;
`
	refreshSessionsPageTemplate = `
with session_ids as (
    select public_id
      from session
     where update_time > @updated_after_time
       and (update_time, public_id) < (@last_item_update_time, @last_item_id)
       and %s -- search condition for applying permissions is constructed
  order by update_time desc, public_id desc
     limit %d
)
  select *
    from session_list
   where session_list.public_id in (select * from session_ids)
order by update_time desc, public_id desc;
`
	estimateCountSessions = `
    select reltuples::bigint as estimate from pg_class where oid in ('session'::regclass)
`

	selectStates = `
  select session_id,
         state,
         lower(active_time_range) as start_time,
         upper(active_time_range) as end_time
    from session_state
   where session_id = ?
order by active_time_range desc;
`
)

const (
	sessionCredentialDynamicBatchInsertBase = `
insert into session_credential_dynamic
	( session_id, library_id, credential_purpose )
values
`
	sessionCredentialDynamicBatchInsertValue = `
  (?, ?, ?)`

	sessionCredentialDynamicBatchInsertReturning = `
  returning session_id, library_id, credential_id, credential_purpose;
`
)

// queries for the delete terminated sessions job
const (
	getDeleteJobParams = `
with total (to_delete) as (
  select count(session_id)
    from session_state
   where session_state.state                    = 'terminated'
     and lower(session_state.active_time_range) < wt_sub_seconds_from_now(@threshold_seconds)
),
params (batch_size) as (
  select batch_size
    from session_delete_terminated_job
)
select total.to_delete                             as total_to_delete,
       params.batch_size                           as batch_size,
       wt_sub_seconds_from_now(@threshold_seconds) as window_start_time
  from total, params;
`
	setDeleteJobBatchSize = `
update session_delete_terminated_job
   set batch_size = @batch_size;
`
	deleteTerminatedInBatch = `
with batch (session_id) as (
  select session_id
    from session_state
   where state                                  = 'terminated'
     and lower(session_state.active_time_range) < @terminated_before
   limit @batch_size
)
delete
  from session
 where public_id in (select session_id from batch);
`
)

func batchInsertSessionCredentialDynamic(creds []*DynamicCredential) (string, []any, error) {
	if len(creds) <= 0 {
		return "", nil, fmt.Errorf("empty slice of DynamicCredential, cannot build query")
	}
	batchInsertParams := make([]string, 0, len(creds))
	batchInsertArgs := make([]any, 0, len(creds)*3)

	for _, cred := range creds {
		batchInsertParams = append(batchInsertParams, sessionCredentialDynamicBatchInsertValue)
		batchInsertArgs = append(batchInsertArgs, []any{cred.SessionId, cred.LibraryId, cred.CredentialPurpose}...)
	}

	q := sessionCredentialDynamicBatchInsertBase + strings.Join(batchInsertParams, ",") + sessionCredentialDynamicBatchInsertReturning

	return q, batchInsertArgs, nil
}
