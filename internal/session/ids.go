// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package session

import (
	"context"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
)

const (
	// StatePrefix for state PK ids
	StatePrefix = "ss"

	// ConnectionPrefix for connection PK ids
	ConnectionPrefix = "sc"

	// ConnectionStatePrefix for connection state PK ids
	ConnectionStatePrefix = "scs"
)

func newId(ctx context.Context) (string, error) {
	const op = "session.newId"
	id, err := db.NewPublicId(ctx, globals.SessionPrefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, op)
	}
	return id, nil
}

func newStateId(ctx context.Context) (string, error) {
	const op = "session.newStateId"
	id, err := db.NewPublicId(ctx, StatePrefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, op)
	}
	return id, nil
}

func newConnectionId(ctx context.Context) (string, error) {
	const op = "session.newConnectionId"
	id, err := db.NewPublicId(ctx, ConnectionPrefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, op)
	}
	return id, nil
}

func newConnectionStateId(ctx context.Context) (string, error) {
	const op = "session.newConnectionStateId"
	id, err := db.NewPublicId(ctx, ConnectionStatePrefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, op)
	}
	return id, nil
}
