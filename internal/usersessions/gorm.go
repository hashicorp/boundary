package usersessions

// TableName returns the table name for the user session.
func (c *Session) TableName() string {
	if c.tableName != "" {
		return c.tableName
	}
	return "user_session"
}

// SetTableName sets the table name.
func (c *Session) SetTableName(n string) {
	if n != "" {
		c.tableName = n
	}
}
