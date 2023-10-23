// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package refreshtoken

import (
	"time"

	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/types/resource"
)

// Item represents a generic resource with a public ID, update time
// and resource type.
type Item struct {
	publicId     string
	updateTime   time.Time
	resourceType resource.Type
}

// GetPublicId gets the public ID of the item.
func (p *Item) GetPublicId() string {
	return p.publicId
}

// GetUpdateTime gets the update time of the item.
func (p *Item) GetUpdateTime() *timestamp.Timestamp {
	return timestamp.New(p.updateTime)
}

// GetResourceType gets the resource type of the item.
func (p *Item) GetResourceType() resource.Type {
	return p.resourceType
}
