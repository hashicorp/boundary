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
		ss.end_time is null
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
		s.connection_limit
	from
		session s
	where
		s.public_id = @session_id
)
select expiration_time, connection_limit, current_connection_count
from
	session_connection_limit, session_connection_count;
`

	sessionPublicIdList = `
select public_id, scope_id, user_id from session
%s
;
`

	sessionList = `
with
session_ids as (
	select public_id
	from session as s
	-- where clause is constructed
	%s
	-- order by clause is constructed
	%s
	-- limit is constructed
	%s
)
select *
from session_list
where
	session_list.public_id in (select * from session_ids)
-- order by clause again since order from cte is not guaranteed to be preserved
%s
;
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
        ss.end_time is null
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
          where public_id in (
          select 
            connection_id
          from 
            session_connection_state
          where 
            state != 'closed' and
            end_time is null
        )
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
		ss.end_time is null
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
		select
			session_id
		from
		  	session_connection
     	where public_id in (
			select
				connection_id
			from
				session_connection_state
			where
				state != 'closed' and
               	end_time is null
    )
);
`

	// closeConnectionsForDeadServersCte finds connections that are:
	//
	// * not closed
	// * belong to servers that have not reported in within an acceptable
	// threshold of time
	//
	// and marks them as closed.
	//
	// The query returns the set of servers that have had connections closed
	// along with their last update time and the number of connections closed on
	// each.
	closeConnectionsForDeadServersCte = `
   with
   dead_workers (worker_id, last_update_time) as (
         select private_id, update_time
           from server_worker
          where update_time < wt_sub_seconds_from_now(@grace_period_seconds)
   ),
   closed_connections (connection_id, worker_id) as (
         update session_connection
            set closed_reason = 'system error'
          where worker_id in (select worker_id from dead_workers)
            and closed_reason is null
      returning public_id, worker_id
   )
   select closed_connections.worker_id,
          dead_workers.last_update_time,
          count(closed_connections.connection_id) as number_connections_closed
     from closed_connections
     join dead_workers
       on closed_connections.worker_id = dead_workers.worker_id
 group by closed_connections.worker_id, dead_workers.last_update_time
 order by closed_connections.worker_id;
`

	orphanedConnectionsCte = `
-- Find connections that are not closed so we can reference those IDs
with
  unclosed_connections as (
    select connection_id
      from session_connection_state
    where
      -- It's the current state
      end_time is null
      -- Current state isn't closed state
      and state in ('authorized', 'connected')
      -- It's not in limbo between when it moved into this state and when
      -- it started being reported by the worker, which is roughly every
      -- 2-3 seconds
      and start_time < wt_sub_seconds_from_now(@worker_state_delay_seconds)
  ),
  connections_to_close as (
	select public_id
	  from session_connection
	 where
		   -- Related to the worker that just reported to us
		   worker_id = @worker_id
		   -- Only unclosed ones
		   and public_id in (select connection_id from unclosed_connections)
		   -- These are connection IDs that just got reported to us by the given
		   -- worker, so they should not be considered closed.
		   %s
  )
update session_connection
   set
	  closed_reason = 'system error'
 where
	public_id in (select public_id from connections_to_close)
returning public_id;
`
	checkIfNotActive = `
select session_id, state
	from session_state ss
where
	(ss.state = 'canceling' or ss.state = 'terminated')
	and ss.end_time is null
	%s
;
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

func batchInsertsessionCredentialDynamic(creds []*DynamicCredential) (string, []interface{}, error) {
	if len(creds) <= 0 {
		return "", nil, fmt.Errorf("empty slice of DynamicCredential, cannot build query")
	}
	batchInsertParams := make([]string, 0, len(creds))
	batchInsertArgs := make([]interface{}, 0, len(creds)*3)

	for _, cred := range creds {
		batchInsertParams = append(batchInsertParams, sessionCredentialDynamicBatchInsertValue)
		batchInsertArgs = append(batchInsertArgs, []interface{}{cred.SessionId, cred.LibraryId, cred.CredentialPurpose}...)
	}

	q := sessionCredentialDynamicBatchInsertBase + strings.Join(batchInsertParams, ",") + sessionCredentialDynamicBatchInsertReturning

	return q, batchInsertArgs, nil
}
