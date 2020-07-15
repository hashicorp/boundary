package authtoken

const defaultAuthTokenTableName = "auth_token"

// TableName returns the table name for the auth token.
func (s *AuthToken) TableName() string {
	if s.tableName != "" {
		return s.tableName
	}
	return defaultAuthTokenTableName
}

// SetTableName sets the table name.  If the caller attempts to
// set the name to "" the name will be reset to the default name.
func (s *AuthToken) SetTableName(n string) {
	switch n {
	case "":
		s.tableName = defaultAuthTokenTableName
	default:
		s.tableName = n
	}
}
