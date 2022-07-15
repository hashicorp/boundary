package plugin

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host"
	"github.com/hashicorp/boundary/internal/types/subtypes"
)

func init() {
	if err := subtypes.Register(host.Domain, Subtype, HostCatalogPrefix, PreviousHostCatalogPrefix, HostSetPrefix, PreviousHostSetPrefix, HostPrefix, PreviousHostPrefix); err != nil {
		panic(err)
	}
}

// PublicId prefixes for the resources in the plugin package.
const (
	HostCatalogPrefix         = "hcplg"
	PreviousHostCatalogPrefix = "hc"
	HostSetPrefix             = "hsplg"
	PreviousHostSetPrefix     = "hs"
	HostPrefix                = "hplg"
	PreviousHostPrefix        = "h"

	Subtype = subtypes.Subtype("plugin")
)

func newHostCatalogId(ctx context.Context) (string, error) {
	id, err := db.NewPublicId(HostCatalogPrefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, "plugin.newHostCatalogId")
	}
	return id, nil
}

func newHostSetId(ctx context.Context) (string, error) {
	id, err := db.NewPublicId(HostSetPrefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, "plugin.newHostSetId")
	}
	return id, nil
}

func newHostId(ctx context.Context, catalogId, externalId string) (string, error) {
	const op = "plugin.newHostId"
	if catalogId == "" {
		return "", errors.New(ctx, errors.InvalidParameter, op, "missing catalog id")
	}
	if externalId == "" {
		return "", errors.New(ctx, errors.InvalidParameter, op, "missing external id")
	}
	id, err := db.NewPublicId(HostPrefix, db.WithPrngValues([]string{catalogId, externalId}))
	if err != nil {
		return "", errors.Wrap(ctx, err, op)
	}
	return id, nil
}
