package plugin

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host"
	"github.com/hashicorp/boundary/internal/types/subtypes"
)

func init() {
	if err := host.Register(Subtype, HostCatalogPrefix, HostSetPrefix); err != nil {
		panic(err)
	}
}

// PublicId prefixes for the resources in the plugin package.
const (
	HostCatalogPrefix = "hcplg"
	HostSetPrefix     = "hsplg"
	HostPrefix        = "hplg"

	Subtype = subtypes.Subtype("plugin")
)

func newHostCatalogId(ctx context.Context, upre string) (string, error) {
	const op = "plugin.newHostCatalogId"
	if upre == "" {
		return "", errors.New(ctx, errors.InvalidParameter, op, "missing plugin id prefix")
	}
	prefix := fmt.Sprintf("%s_%s", HostCatalogPrefix, upre)
	id, err := db.NewPublicId(prefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, op)
	}
	return id, nil
}

func newHostSetId(ctx context.Context, upre string) (string, error) {
	const op = "plugin.newHostSetId"
	if upre == "" {
		return "", errors.New(ctx, errors.InvalidParameter, op, "missing plugin id prefix")
	}
	prefix := fmt.Sprintf("%s_%s", HostSetPrefix, upre)
	id, err := db.NewPublicId(prefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, op)
	}
	return id, nil
}

func newHostId(ctx context.Context, upre string, catalogId, externalId string) (string, error) {
	const op = "plugin.newHostId"
	if upre == "" {
		return "", errors.New(ctx, errors.InvalidParameter, op, "missing plugin id prefix")
	}
	if catalogId == "" {
		return "", errors.New(ctx, errors.InvalidParameter, op, "missing catalog id")
	}
	if externalId == "" {
		return "", errors.New(ctx, errors.InvalidParameter, op, "missing external id")
	}
	prefix := fmt.Sprintf("%s_%s", HostPrefix, upre)
	id, err := db.NewPublicId(prefix, db.WithPrngValues([]string{catalogId, externalId}))
	if err != nil {
		return "", errors.Wrap(ctx, err, op)
	}
	return id, nil
}
