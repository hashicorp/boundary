package static

// TableName returns the table name for the host catalog.
func (c *HostCatalog) TableName() string {
	if c.tableName != "" {
		return c.tableName
	}
	return "static_host_catalog"
}

// SetTableName sets the table name. If the caller attempts to
// set the name to "" the name will be reset to the default name.
func (c *HostCatalog) SetTableName(n string) {
	c.tableName = n
}

// TableName returns the table name for the host.
func (h *Host) TableName() string {
	if h.tableName != "" {
		return h.tableName
	}
	return "static_host"
}

// SetTableName sets the table name. If the caller attempts to
// set the name to "" the name will be reset to the default name.
func (h *Host) SetTableName(n string) {
	h.tableName = n
}

// TableName returns the table name for the host set.
func (s *HostSet) TableName() string {
	if s.tableName != "" {
		return s.tableName
	}
	return "static_host_set"
}

// SetTableName sets the table name. If the caller attempts to
// set the name to "" the name will be reset to the default name.
func (s *HostSet) SetTableName(n string) {
	s.tableName = n
}

// TableName returns the table name for the host set.
func (m *HostSetMember) TableName() string {
	if m.tableName != "" {
		return m.tableName
	}
	return "static_host_set_member"
}

// SetTableName sets the table name. If the caller attempts to
// set the name to "" the name will be reset to the default name.
func (m *HostSetMember) SetTableName(n string) {
	m.tableName = n
}
