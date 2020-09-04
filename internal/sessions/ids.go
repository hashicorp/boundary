package sessions

import (
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
)

const (
	SessionPrefix      = "s"
	SessionStatePrefix = "ss"
)

func newSessionId() (string, error) {
	id, err := db.NewPublicId(SessionPrefix)
	if err != nil {
		return "", fmt.Errorf("new session id: %w", err)
	}
	return id, nil
}

func newSessionStateId() (string, error) {
	id, err := db.NewPublicId(SessionStatePrefix)
	if err != nil {
		return "", fmt.Errorf("new session state id: %w", err)
	}
	return id, nil
}
