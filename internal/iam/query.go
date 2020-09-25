package iam

// query.go contains "raw sql" for the iam package that goes directly against
// the db via sql.DB vs the standard pattern of using the internal/db package to
// interact with the db.
const (
	// whereUserAccount - given an auth account id, return the associated user.
	whereUserAccount = `	
	select iam_user.*
		from iam_user 
	inner join auth_account 
		on iam_user.public_id = auth_account.iam_user_id
	where 
		iam_user.scope_id = auth_account.scope_id and
		auth_account.public_id = $1`

	// whereValidAuthMethod - determine if an auth method public_id within a scope_id
	// is valid by returning a count of matching rows.
	whereValidAuthMethod = `select count(*) from auth_method where public_id = $1 and scope_id = $2`

	// insertAuthMethod - insert a row directly into auth_method (TODO - this
	// should be replaced with calls to the auth method repo).
	insertAuthMethod = `insert into auth_method (public_id, scope_id) values ($1, $2)`

	accountChangesQuery = `
	with
	final_accounts (account_id) as (
	  -- returns the SET list
	  select public_id
		from auth_account
	   where public_id in (%s)
	),
	current_accounts (account_id) as (
	  -- returns the current list
	  select public_id
		from auth_account
	   where iam_user_id = $1
	),
	keep_accounts (account_id) as (
	  -- returns the KEEP list
	  select account_id
		from current_accounts
	   where account_id in (select * from final_accounts)
	),
	delete_accounts (account_id) as (
	  -- returns the DELETE list
	  select account_id
		from current_accounts
	   where account_id not in (select * from final_accounts)
	),
	insert_accounts (account_id) as (
	  -- returns the ADD list
	  select account_id
		from final_accounts
	   where account_id not in (select * from keep_accounts)
	),
	final (action, account_id) as (
	  select 'disassociate', account_id
		from delete_accounts
	   union
	  select 'associate', account_id
		from insert_accounts
	)
	select * from final
	order by action, account_id;
	`
)
