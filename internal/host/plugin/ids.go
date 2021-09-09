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
	// TODO: Pull these out of being constants and have them derivable at run time.
	HostCatalogPrefix = "hcplg"
	HostSetPrefix     = "hsplg"

	Subtype = subtypes.Subtype("plugin")
)

func newHostCatalogId(ctx context.Context, upre string) (string, error) {
	prefix := fmt.Sprintf("%s_%s", HostCatalogPrefix, upre)
	id, err := db.NewPublicId(prefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, "plugin.newHostCatalogId")
	}
	return id, nil
}

func newHostSetId(ctx context.Context, upre string) (string, error) {
	prefix := fmt.Sprintf("%s_%s", HostSetPrefix, upre)
	id, err := db.NewPublicId(prefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, "plugin.newHostSetId")
	}
	return id, nil
}
