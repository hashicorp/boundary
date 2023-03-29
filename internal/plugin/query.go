package plugin

const (
	addSupportFlagQuery = "insert into %s (public_id) values (?) on conflict do nothing;"
)
