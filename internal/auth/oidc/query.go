package oidc

const (
	acctUpsertQuery = `
		insert into auth_oidc_account
			(
				public_id, 			-- $1
				auth_method_id, 	-- $2
				issuer_id, 			-- $3
				subject_id, 		-- $4
				full_name, 			-- $5
				email	 			-- $6
			)
		values
			($1, $2, $3, $4, $5, $6)
		on conflict on constraint 
			auth_method_id_issuer_id_subject_id_unique
		do update set
			full_name = $2,
			email = $3;
	`
)
