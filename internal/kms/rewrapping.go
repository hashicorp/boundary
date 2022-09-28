package kms

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"golang.org/x/exp/maps"
)

type RewrapFn func(ctx context.Context, dataKeyVersionId string, reader db.Reader, writer db.Writer, kms *Kms) error

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
