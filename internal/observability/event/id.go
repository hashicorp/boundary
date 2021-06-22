package event

import (
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
)

func newId(prefix string) (string, error) {
	const op = "event.newId"
	id, err := db.NewPublicId(prefix)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}
	return id, nil
}
