package target

import (
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
)

const (
	TcpTargetPrefix = "ttcp"
)

func newTcpTargetId() (string, error) {
	const op = "target.newTcpTargetId"
	id, err := db.NewPublicId(TcpTargetPrefix)
	if err != nil {
		return "", errors.WrapDeprecated(err, op)
	}
	return id, nil
}
