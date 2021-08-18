package session

import (
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
)

const (
	// SessionPrefix for session PK ids
	SessionPrefix = "s"

	// StatePrefix for state PK ids
	StatePrefix = "ss"

	// ConnectionPrefix for connection PK ids
	ConnectionPrefix = "sc"

	// ConnectionStatePrefix for connection state PK ids
	ConnectionStatePrefix = "scs"
)

func newId() (string, error) {
	const op = "session.newId"
	id, err := db.NewPublicId(SessionPrefix)
	if err != nil {
		return "", errors.WrapDeprecated(err, op)
	}
	return id, nil
}

func newStateId() (string, error) {
	const op = "session.newStateId"
	id, err := db.NewPublicId(StatePrefix)
	if err != nil {
		return "", errors.WrapDeprecated(err, op)
	}
	return id, nil
}

func newConnectionId() (string, error) {
	const op = "session.newConnectionId"
	id, err := db.NewPublicId(ConnectionPrefix)
	if err != nil {
		return "", errors.WrapDeprecated(err, op)
	}
	return id, nil
}

func newConnectionStateId() (string, error) {
	const op = "session.newConnectionStateId"
	id, err := db.NewPublicId(ConnectionStatePrefix)
	if err != nil {
		return "", errors.WrapDeprecated(err, op)
	}
	return id, nil
}
