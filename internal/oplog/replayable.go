// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oplog

// ReplayableMessage defines an interface for messages that can be replayed from
// the oplog entries.  we need to be able to replay into different table names.
type ReplayableMessage interface {
	// TableName returns the table name of the resource
	TableName() string
	// SetTableName sets the table name of the resource
	SetTableName(name string)
}
