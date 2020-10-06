package session

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
		ss.session_id = $1 and 
		s.version = $2 and
		s.public_id not in(select session_id from session_state where session_id = $1 and state = 'active') 
)
select * from not_active;
`

	// updateSessionState checks that we don't already have a row for the new
	// state or it's not already terminated (final state) before inserting a new
	// state.
	updateSessionState = `
insert into session_state(session_id, state) 
select
	$1::text, $2 
from
	session s
where 
	s.public_id = $1::text and
	s.public_id not in (
		select 
			session_id 
		from 
			session_state 
		where 
			-- already in the updated state
			(
				session_id = $1::text and 
				state = $2
			) or
			-- already terminated
			session_id in (
				select 
					session_id 
				from 
					session_state 
				where 
					session_id = $1::text and 
					state = 'terminated'
			)
	) 
`

	terminateSessionCte = `
insert into session_state
with terminated as (
	select s.public_id, 'terminated' as state
	from 
		session s
	where 
		s.version = $2  and
		s.public_id in (
			-- sessions without any connections
			select s.public_id 
			from 
				session s
			left join session_connection sc on sc.session_id = s.public_id 
			where 
				sc.session_id is null
				and s.public_id = $1
			union
			-- sessions where all connections are closed
			select s.public_id 
			from
				session s,
				session_connection c,
				session_connection_state cs
			where
				s.public_id = c.session_id and
				c.public_id = cs.connection_id and
				cs.state = 'closed' and 
				s.public_id = $1
		) 
)
select * from terminated;
`
	authorizeConnectionCte = `
insert into session_connection (
	session_id, 
	public_id
)
with active_session as ( 
	select 
		$1 as session_id,
		$2 as public_id
	from
		session s
	where
		-- check that the session hasn't expired.
		s.expiration_time > now() and
		-- check that there are still connections available. connection_limit of -1 equals unlimited connections
		(
			s.connection_limit = -1
				or 
			s.connection_limit > (select count(*) from session_connection sc where sc.session_id = $1)
		) and
		-- check that there's a state of active
		s.public_id in (
			select 
				ss.session_id 
			from 
				session_state ss
			where 
				ss.session_id = $1 and 
				ss.state = 'active' and
				-- if there's no end_time, then this is the current state.
				ss.end_time is null 
		) 
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
		sc.session_id = $1
),
session_connection_limit(expiration_time, connection_limit) as (
	select 
		s.expiration_time,
		s.connection_limit
	from
		session s
	where 
		s.public_id = $1
)
select expiration_time, connection_limit, current_connection_count 
from  
	session_connection_limit, session_connection_count;	
`
	sessionList = `
select * 
from
	(select public_id from session %s) s,
	session_with_state ss
where 
	s.public_id = ss.public_id 
	%s
%s
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
)
`
)
