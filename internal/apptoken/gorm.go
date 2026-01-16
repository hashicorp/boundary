// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken

const (
	// defaultAppTokenViewName is the name of the database view that unions
	// app_token_global, app_token_org, and app_token_project tables.
	defaultAppTokenViewName = "app_token_view"
)

// TableName returns the table name for the appTokenView.
func (atv *appTokenView) TableName() string {
	if atv.tableName != "" {
		return atv.tableName
	}
	return defaultAppTokenViewName
}

// SetTableName sets the table name. If the caller attempts to
// set the name to "" the name will be reset to the default name.
func (atv *appTokenView) SetTableName(n string) {
	atv.tableName = n
}
