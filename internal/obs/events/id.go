package event

import (
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
)

func newId(prefix string) (string, error) {
	const op = "event.newId"
	id, err := db.NewPublicId(prefix)
	if err != nil {
		return "", errors.Wrap(err, "iam.newRoleId")
	}
	return id, nil
}
