// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package kms

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"golang.org/x/exp/maps"
)

// GetWrapperer defines (and constrains) the kms features required by the
// RewrapFn
type GetWrapperer interface {
	// GetWrapper returns a wrapper for the given scope and purpose.
	GetWrapper(ctx context.Context, scopeId string, purpose KeyPurpose, opt ...Option) (wrapping.Wrapper, error)
}

type RewrapFn func(ctx context.Context, dataKeyVersionId string, scopeId string, reader db.Reader, writer db.Writer, kms GetWrapperer) error

var tableNameToRewrapFn = map[string]RewrapFn{}

// RegisterTableRewrapFn registers a function to be used to rewrap data in a specific table with a new key
func RegisterTableRewrapFn(tableName string, rewrapFn RewrapFn) {
	if _, ok := tableNameToRewrapFn[tableName]; ok {
		panic(fmt.Sprintf("rewrap function for table name %q already exists", tableName))
	}
	tableNameToRewrapFn[tableName] = rewrapFn
}

// ListTablesSupportingRewrap lists all the table names registered with a rewrap function
func ListTablesSupportingRewrap() []string {
	return maps.Keys(tableNameToRewrapFn)
}
