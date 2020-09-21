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
	// state before inserting a new state.
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
			session_id = $1::text and 
			state = $2
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
)
