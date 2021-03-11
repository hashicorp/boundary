package oidc

const (
	acctUpsertQuery = `
		insert into auth_oidc_account
			(%s)
		values
			(%s)
		on conflict on constraint 
			auth_method_id_issuer_id_subject_id_unique
		do update set
			%s
	`
)
