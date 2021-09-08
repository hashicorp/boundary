package plugin

import (
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

func newHostCatalogId() (string, error) {
	// TODO: Take in a prefix portion as an argument.
	id, err := db.NewPublicId(HostCatalogPrefix)
	if err != nil {
		return "", errors.WrapDeprecated(err, "plugin.newHostCatalogId")
	}
	return id, nil
}

func newHostSetId() (string, error) {
	// TODO: Take in a prefix portion as an argument.
	id, err := db.NewPublicId(HostSetPrefix)
	if err != nil {
		return "", errors.WrapDeprecated(err, "plugin.newHostSetId")
	}
	return id, nil
}
