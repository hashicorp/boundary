package servers

const (
	serverUpsertQuery = `
		insert into server
			(private_id, type, description, address, update_time)
		values
			($1, $2, $3, $4, now())
		on conflict on constraint server_pkey
		do update set
			type = $2,
			description = $3,
			address = $4,
			update_time = now();
	`
	deleteWhereCreateTimeSql = `create_time < $1`
	deleteTagsSql            = `server_id = $1`
)
