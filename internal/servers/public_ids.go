package servers

import (
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
)

// PublicId prefixes for the resources in the servers package.
const (
	WorkerPrefix = "w"
)

func newWorkerId() (string, error) {
	id, err := db.NewPublicId(WorkerPrefix)
	if err != nil {
		return "", errors.WrapDeprecated(err, "vault.newCredentialStoreId")
	}
	return id, nil
}
