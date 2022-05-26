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

func newWorkerIdFromName(ctx context.Context, name string) (string, error) {
	id, err := db.NewPublicId(WorkerPrefix, db.WithPrngValues([]string{name}))
	if err != nil {
		return "", errors.Wrap(ctx, err, "servers.newWorkerId")
	}
	return id, nil
}
