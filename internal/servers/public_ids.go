package servers

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
)

// PublicId prefixes for the resources in the servers package.
const (
	WorkerPrefix = "w"
)

func newWorkerId(ctx context.Context) (string, error) {
	id, err := db.NewPublicId(WorkerPrefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, "servers.newWorkerId")
	}
	return id, nil
}

// newWorkerIdFromScopeAndName generates a predictable public id based on the
// scope and the worker name.  This should only be used on kms workers at in
// upsert.
func newWorkerIdFromScopeAndName(ctx context.Context, scope, name string) (string, error) {
	const op = "servers.newWorkerIdFromScopeAndName"
	id, err := db.NewPublicId(WorkerPrefix, db.WithPrngValues([]string{scope, name}))
	if err != nil {
		return "", errors.Wrap(ctx, err, "servers.newWorkerId")
	}
	return id, nil
}
