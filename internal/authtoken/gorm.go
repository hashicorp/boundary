package authtoken

// TableName returns the table name for the auth token.
func (s *AuthToken) TableName() string {
	if s.tableName == "" {
		return "auth_token_account"
	}
	return s.tableName
}

// SetTableName sets the table name.
func (s *AuthToken) SetTableName(n string) {
	s.tableName = n
}

// TableName returns the table name for the auth token.
func (s *writableAuthToken) TableName() string {
	if s.tableName == "" {
		return "auth_token"
	}
	return s.tableName
}

// SetTableName sets the table name.
func (s *writableAuthToken) SetTableName(n string) {
	s.tableName = n
}
