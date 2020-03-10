package store

// TableName overrides the gorm database table for the store.Oplog messages
func (*Entry) TableName() string { return "oplog_entries" }

// TableName overrides the gorm database table for the store.Ticket messages
func (*Ticket) TableName() string { return "oplog_tickets" }

// TableName overrides the gorm database table for the store.Metadata messages
func (*Metadata) TableName() string { return "oplog_metadata" }
