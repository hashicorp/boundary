package session

import (
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
)

const (
	SessionPrefix = "s"
	StatePrefix   = "ss"
)

func newId() (string, error) {
	id, err := db.NewPublicId(SessionPrefix)
	if err != nil {
		return "", fmt.Errorf("new session id: %w", err)
	}
	return id, nil
}

func newStateId() (string, error) {
	id, err := db.NewPublicId(StatePrefix)
	if err != nil {
		return "", fmt.Errorf("new session state id: %w", err)
	}
	return id, nil
}
