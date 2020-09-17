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

	terminateSessionCte = `
	insert into session_state
	with terminated as (
		select s.public_id, 'terminated' as state
		from 
			session s
		where 
			s.version = 1  and
			s.public_id in (
				-- sesions without any connections
				select s.public_id 
				from 
					session s
				left join session_connection sc ON sc.session_id = s.public_id 
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
)
