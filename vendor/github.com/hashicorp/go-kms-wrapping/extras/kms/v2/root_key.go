// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kms

import (
	"fmt"
	"time"
)

// rootKey represents the KEKs (keys to encrypt keys) of the system.
type rootKey struct {
	// PrivateId is used to access the root key
	PrivateId string `json:"private_id,omitempty" gorm:"primary_key"`
	// ScopeId for the root key
	ScopeId string `json:"scope_id,omitempty" gorm:"default:null"`
	// CreateTime from the db
	CreateTime time.Time `json:"create_time,omitempty" gorm:"default:current_timestamp"`

	// tableNamePrefix defines the prefix to use before the table name and
	// allows us to support custom prefixes as well as multi KMSs within a
	// single schema.
	tableNamePrefix string `gorm:"-"`
}

// newRootKey creates a new in memory root key. No optionsare currently
// supported.
func newRootKey(scopeId string, _ ...Option) (*rootKey, error) {
	const op = "kms.NewRootKey"
	if scopeId == "" {
		return nil, fmt.Errorf("%s: missing scope id: %w", op, ErrInvalidParameter)
	}
	c := &rootKey{
		ScopeId: scopeId,
	}
	return c, nil
}

// TableName returns the table name
func (k *rootKey) TableName() string {
	const tableName = "root_key"
	return fmt.Sprintf("%s_%s", k.tableNamePrefix, tableName)
}

// Clone creates a clone of the RootKeyVersion
func (k *rootKey) Clone() *rootKey {
	return &rootKey{
		PrivateId:       k.PrivateId,
		ScopeId:         k.ScopeId,
		CreateTime:      k.CreateTime,
		tableNamePrefix: k.tableNamePrefix,
	}
}

// GetPrivateId returns the key's private id
func (k *rootKey) GetPrivateId() string { return k.PrivateId }
