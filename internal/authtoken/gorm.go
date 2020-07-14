package authtoken

// TableName returns the table name for the auth token.
func (s *AuthToken) TableName() string {
	if s.tableName != "" {
		return s.tableName
	}
	return "auth_token"
}

// SetTableName sets the table name.
func (s *AuthToken) SetTableName(n string) {
	if n != "" {
		s.tableName = n
	}
}
