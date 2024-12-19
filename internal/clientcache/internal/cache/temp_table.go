package cache

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/util"
)

type resourceTabler interface {
	TableName() string
}

const (
	tmpTblSuffix           = "_refresh_window"
	targetTblName          = "target"
	sessionTblName         = "session"
	resolvableAliasTblName = "resolvable_alias"
)

func tempTableName(ctx context.Context, resource resourceTabler) (string, error) {
	const op = "cache.tempTableName"
	switch {
	case util.IsNil(resource):
		return "", errors.New(ctx, errors.InvalidParameter, op, "missing resource tabler")
	}
	baseTableName := strings.ToLower(resource.TableName())
	switch baseTableName {
	case targetTblName, sessionTblName, resolvableAliasTblName:
	default:
		return "", errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("unable to create a temp table for %s, it is not a supported base table for creating a temp table", baseTableName))
	}
	return baseTableName + tmpTblSuffix, nil
}
