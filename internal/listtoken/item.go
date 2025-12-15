// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package listtoken

import (
	"errors"

	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/types/resource"
)

// Item represents a generic resource with a public ID,
// create time, update time and resource type.
type Item struct {
	publicId string
	// Only one of these two is ever set at a time.
	// In the case of a pagination token item, it will
	// be the create time. In the case of a refresh token,
	// it's the update time.
	createTime   *timestamp.Timestamp
	updateTime   *timestamp.Timestamp
	resourceType resource.Type
}

// GetPublicId gets the public ID of the item.
func (p *Item) GetPublicId() string {
	return p.publicId
}

// GetCreateTime gets the create time of the item.
func (p *Item) GetCreateTime() *timestamp.Timestamp {
	return p.createTime
}

// GetUpdateTime gets the update time of the item.
func (p *Item) GetUpdateTime() *timestamp.Timestamp {
	return p.updateTime
}

// GetResourceType gets the resource type of the item.
func (p *Item) GetResourceType() resource.Type {
	return p.resourceType
}

// Validate can be called to validate that an Item
// is valid.
func (p *Item) Validate() error {
	switch {
	case p.publicId == "":
		return errors.New("missing public id")
	case p.resourceType == resource.Unknown:
		return errors.New("missing resource type")
	case p.createTime != nil && p.updateTime != nil:
		return errors.New("both create time and update time is set")
	case p.createTime == nil && p.updateTime == nil:
		return errors.New("neither create time nor update time is set")
	}
	return nil
}
