// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package alias

import (
	"github.com/hashicorp/boundary/internal/types/resource"
)

const (
	Domain = "alias"
)

// An Alias is a view object containing only the information needed to lookup
// generic information about an alias.
type Alias struct {
	tableName     string `gorm:"-"`
	PublicId      string `gorm:"primary_key"`
	DestinationId string
	Value         string
}

// allocAlias is just easier/better than leaking the underlying type
// bits to the repo, since the repo needs to alloc this type quite often.
func allocAlias() *Alias {
	fresh := &Alias{}
	return fresh
}

// GetResourceType returns the resource type of the Alias
func (al Alias) GetResourceType() resource.Type {
	return resource.Alias
}

func (al *Alias) TableName() string {
	if al.tableName != "" {
		return al.tableName
	}
	return "alias_all_subtypes"
}

func (al *Alias) SetTableName(tableName string) {
	al.tableName = tableName
}
