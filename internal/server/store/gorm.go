// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package store

// TableName overrides the table name used by Controller to `server_controller`
func (*Controller) TableName() string {
	return "server_controller"
}

// TableName overrides the table name used by ApiTag
func (w *ApiTag) TableName() string {
	return "server_worker_api_tag"
}

// TableName overrides the table name used by ConfigTag
func (w *ConfigTag) TableName() string {
	return "server_worker_config_tag"
}
