// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package hostcatalogs

import (
	"fmt"

	"github.com/hashicorp/eventlogger/filters/encrypt"
)

// Tags implements the encrypt.Taggable interface which allows
// HostCatalog map fields to be classified for the encrypt filter.
func (req *HostCatalog) Tags() ([]encrypt.PointerTag, error) {
	tags := make([]encrypt.PointerTag, 0, len(req.AuthorizedCollectionActions))
	for k := range req.AuthorizedCollectionActions {
		tags = append(tags, encrypt.PointerTag{
			Pointer:        fmt.Sprintf("/AuthorizedCollectionActions/%s", k),
			Classification: encrypt.PublicClassification,
		})
	}
	return tags, nil
}
