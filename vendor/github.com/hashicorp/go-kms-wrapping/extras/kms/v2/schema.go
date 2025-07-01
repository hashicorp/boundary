// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kms

import (
	"fmt"
	"time"
)

// schema represents the current schema in the database
type schema struct {
	// Version of the schema
	Version string
	// UpdateTime is the last update of the version
	UpdateTime time.Time
	// CreateTime is the create time of the initial version
	CreateTime time.Time

	// tableNamePrefix defines the prefix to use before the table name and
	// allows us to support custom prefixes as well as multi KMSs within a
	// single schema.
	tableNamePrefix string `gorm:"-"`
}

// TableName returns the table name
func (k *schema) TableName() string {
	const tableName = "schema_version"
	return fmt.Sprintf("%s_%s", k.tableNamePrefix, tableName)
}
