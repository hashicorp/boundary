package static

import (
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
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
		return "", fmt.Errorf("new host catalog id: %w", err)
	}
	return id, err
}

func newHostId() (string, error) {
	id, err := db.NewPublicId(HostPrefix)
	if err != nil {
		return "", fmt.Errorf("new host id: %w", err)
	}
	return id, err
}

func newHostSetId() (string, error) {
	id, err := db.NewPublicId(HostSetPrefix)
	if err != nil {
		return "", fmt.Errorf("new host set id: %w", err)
	}
	return id, err
}
