package static

const (
	defaultHostCatalogTableName   = "static_host_catalog"
	defaultHostTableName          = "static_host"
	defaultHostSetTableName       = "static_host_set"
	defaultHostSetMemberTableName = "static_host_set_member"
)

// TableName returns the table name for the host catalog.
func (c *HostCatalog) TableName() string {
	if c.tableName != "" {
		return c.tableName
	}
	return defaultHostCatalogTableName
}

// SetTableName sets the table name. If the caller attempts to
// set the name to "" the name will be reset to the default name.
func (c *HostCatalog) SetTableName(n string) {
	switch n {
	case "":
		c.tableName = defaultHostCatalogTableName
	default:
		c.tableName = n
	}
}

// TableName returns the table name for the host.
func (h *Host) TableName() string {
	if h.tableName != "" {
		return h.tableName
	}
	return defaultHostTableName
}

// SetTableName sets the table name. If the caller attempts to
// set the name to "" the name will be reset to the default name.
func (h *Host) SetTableName(n string) {
	switch n {
	case "":
		h.tableName = defaultHostTableName
	default:
		h.tableName = n
	}
}

// TableName returns the table name for the host set.
func (s *HostSet) TableName() string {
	if s.tableName != "" {
		return s.tableName
	}
	return defaultHostSetTableName
}

// SetTableName sets the table name. If the caller attempts to
// set the name to "" the name will be reset to the default name.
func (s *HostSet) SetTableName(n string) {
	switch n {
	case "":
		s.tableName = defaultHostSetTableName
	default:
		s.tableName = n
	}
}

// TableName returns the table name for the host set.
func (m *HostSetMember) TableName() string {
	if m.tableName != "" {
		return m.tableName
	}
	return defaultHostSetMemberTableName
}

// SetTableName sets the table name. If the caller attempts to
// set the name to "" the name will be reset to the default name.
func (m *HostSetMember) SetTableName(n string) {
	switch n {
	case "":
		m.tableName = defaultHostSetMemberTableName
	default:
		m.tableName = n
	}
}
