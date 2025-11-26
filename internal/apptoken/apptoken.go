// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken

import (
	"time"

	"github.com/hashicorp/boundary/internal/db/timestamp"
)

// An AppToken is an application token used for machine-to-machine authentication.
type AppToken struct {
	PublicId                  string
	ScopeId                   string
	Name                      string
	Description               string
	CreateTime                *timestamp.Timestamp
	ApproximateLastAccessTime *timestamp.Timestamp
	ExpirationTime            *timestamp.Timestamp
	TimeToStaleSeconds        uint32
	Token                     string // Token is a plaintext value of the token
	CreatedByUserId           string
	KeyId                     string
	Revoked                   bool
	Permissions               []AppTokenPermission
}

// AppTokenPermission represents the permissions granted to an AppToken.
// The individual scopes granted to an AppTokenPermission will remain constant over time.
// When a scope is removed, it is moved from GrantedScopes to DeletedScopes.
// The union of GrantedScopes and DeletedScopes will always equal the original set of granted scopes.
type AppTokenPermission struct {
	Label         string
	Grants        []string
	GrantedScopes []string
	DeletedScopes []DeletedScope
}

// DeletedScope represents a scope which has been deleted from an AppTokenPermission.
type DeletedScope struct {
	ScopeId   string
	TimeStamp *timestamp.Timestamp
}

// Methods

// IsActive returns true if the app token is active (not revoked and not expired)
// An AppToken is considered inactive if:
//   - Token is revoked
//   - time.Now() is after expiration time
//   - time.Now() is after lastAccess + timeToStaleSeconds
func (a *AppToken) IsActive() bool {
	now := time.Now()

	switch {
	case a.Revoked:
		return false
	case a.ExpirationTime != nil && now.After(a.ExpirationTime.AsTime()):
		return false
	case a.TimeToStaleSeconds > 0 && a.ApproximateLastAccessTime != nil &&
		now.After(a.ApproximateLastAccessTime.AsTime().Add(time.Duration(a.TimeToStaleSeconds)*time.Second)):
		return false
	default:
		return true
	}
}
