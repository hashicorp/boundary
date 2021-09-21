package vault

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
)

const (
	usernamePasswordMapPrefix = "cmvltup"
)

func newUsernamePasswordMapId(ctx context.Context) (string, error) {
	const op = "vault.newUsernamePasswordMapId"
	id, err := db.NewPrivateId(usernamePasswordMapPrefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, op)
	}
	return id, nil
}
