package servers

const (
	serverUpsertQuery = `
		insert into server
			(private_id, type, description, address, update_time)
		values
			(@private_id, @type, @description, @address, now())
		on conflict on constraint server_pkey
		do update set
			type = @type,
			description = @description,
			address = @address,
			update_time = now();
	`
	deleteWhereCreateTimeSql = `create_time < ?`
	deleteTagsSql            = `server_id = ?`
)
