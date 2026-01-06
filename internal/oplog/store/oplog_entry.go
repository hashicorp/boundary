// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package store

// TableName overrides the gorm database table for the store.Oplog messages
func (*Entry) TableName() string { return "oplog_entry" }

// TableName overrides the gorm database table for the store.Ticket messages
func (*Ticket) TableName() string { return "oplog_ticket" }

// TableName overrides the gorm database table for the store.Metadata messages
func (*Metadata) TableName() string { return "oplog_metadata" }
