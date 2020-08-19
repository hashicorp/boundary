package target

import (
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
)

const (
	TcpTargetPrefix = "tcp"
)

func newTcpId() (string, error) {
	id, err := db.NewPublicId(TcpTargetPrefix)
	if err != nil {
		return "", fmt.Errorf("new tcp target id: %w", err)
	}
	return id, nil
}
