// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package refreshtoken

import (
	"time"

	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/types/resource"
)

type item struct {
	publicId     string
	updateTime   time.Time
	resourceType resource.Type
}

func (p *item) GetPublicId() string {
	return p.publicId
}

func (p *item) GetUpdateTime() *timestamp.Timestamp {
	return timestamp.New(p.updateTime)
}

func (p *item) GetResourceType() resource.Type {
	return p.resourceType
}
