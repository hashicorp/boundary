package static

import (
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
)

// PublicId prefixes for the resources in the static package.
const (
	HostCatalogPrefix = "hcst"
	HostSetPrefix     = "hsst"
	HostPrefix        = "hst"
)

func newHostCatalogId() (string, error) {
	id, err := db.NewPublicId(HostCatalogPrefix)
	if err != nil {
		return "", errors.Wrap(err, errors.WithMsg("new host catalog id"))
	}
	return id, err
}

func newHostId() (string, error) {
	id, err := db.NewPublicId(HostPrefix)
	if err != nil {
		return "", errors.Wrap(err, errors.WithMsg("new host id"))
	}
	return id, err
}

func newHostSetId() (string, error) {
	id, err := db.NewPublicId(HostSetPrefix)
	if err != nil {
		return "", errors.Wrap(err, errors.WithMsg("new host set id"))
	}
	return id, err
}
