package usersessions

// TableName returns the table name for the user session.
func (s *Session) TableName() string {
	if s.tableName != "" {
		return s.tableName
	}
	return "user_session"
}

// SetTableName sets the table name.
func (s *Session) SetTableName(n string) {
	if n != "" {
		s.tableName = n
	}
}
