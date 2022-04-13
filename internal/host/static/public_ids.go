package static

import (
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host"
	"github.com/hashicorp/boundary/internal/types/subtypes"
)

func init() {
	if err := subtypes.Register(host.Domain, Subtype, HostCatalogPrefix, HostSetPrefix, HostPrefix); err != nil {
		panic(err)
	}
}

// PublicId prefixes for the resources in the static package.
const (
	HostCatalogPrefix = "hcst"
	HostSetPrefix     = "hsst"
	HostPrefix        = "hst"

	Subtype = subtypes.Subtype("static")
)

func newHostCatalogId() (string, error) {
	id, err := db.NewPublicId(HostCatalogPrefix)
	if err != nil {
		return "", errors.WrapDeprecated(err, "static.newHostCatalogId")
	}
	return id, nil
}

func newHostId() (string, error) {
	id, err := db.NewPublicId(HostPrefix)
	if err != nil {
		return "", errors.WrapDeprecated(err, "static.newHostId")
	}
	return id, nil
}

func newHostSetId() (string, error) {
	id, err := db.NewPublicId(HostSetPrefix)
	if err != nil {
		return "", errors.WrapDeprecated(err, "static.newHostSetId")
	}
	return id, nil
}
