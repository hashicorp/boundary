// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package authtoken

const (
	// defaultAuthTokenTableName is the table where auth tokens are stored.
	defaultAuthTokenTableName = "auth_token"

	// defaultAuthTokenViewName is a view that includes all the auth_token
	// columns plus the auth_account columns of: scope_id, iam_user_id and
	// auth_method_id.  These additional columns are returned via the API for
	// auth tokens, so the view's handy
	defaultAuthTokenViewName = "auth_token_account"
)

// TableName returns the table name for the auth token.
func (s *AuthToken) TableName() string {
	if s.tableName != "" {
		return s.tableName
	}
	return defaultAuthTokenTableName
}

// SetTableName sets the table name.  If the caller attempts to
// set the name to "" the name will be reset to the default name.
func (s *AuthToken) SetTableName(n string) {
	s.tableName = n
}

// TableName returns the table name for the authTokenView.
func (s *authTokenView) TableName() string {
	if s.tableName != "" {
		return s.tableName
	}
	return defaultAuthTokenViewName
}

// SetTableName sets the table name.  If the caller attempts to
// set the name to "" the name will be reset to the default name.
func (s *authTokenView) SetTableName(n string) {
	s.tableName = n
}
