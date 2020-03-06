package store

func (*Entry) TableName() string { return "oplog_entries" }

func (*Ticket) TableName() string { return "oplog_tickets" }

func (*Metadata) TableName() string { return "oplog_metadata" }
