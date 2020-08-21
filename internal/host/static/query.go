package static

const (
	setMembersQueryNoLimit = `
select *
  from static_host
 where public_id in
       ( select host_id
           from static_host_set_member
          where set_id = $1
       );
`

	setMembersQueryLimit = `
select *
  from static_host
 where public_id in
       ( select host_id
           from static_host_set_member
          where set_id = $1
		  limit $2
       );
`
)
