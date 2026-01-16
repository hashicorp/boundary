// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package session

import (
	"context"

	"github.com/hashicorp/boundary/internal/errors"
)

// AuthorizeConnection is a domain service function that will create a Connection
// for a session if the following criteria are met:
// * The session is active.
// * The session is not expired.
// * The session has not reached its connection limit or has a connection limit of -1.
// If any of these criteria is not met, it returns an error with Code InvalidSessionState.
func AuthorizeConnection(ctx context.Context, sessionRepoFn *Repository, connectionRepoFn *ConnectionRepository,
	sessionId, workerId string, opt ...Option,
) (*Connection, *AuthzSummary, error) {
	const op = "session.AuthorizeConnection"

	connection, err := connectionRepoFn.AuthorizeConnection(ctx, sessionId, workerId)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}

	authzSummary, err := sessionRepoFn.sessionAuthzSummary(ctx, sessionId)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	return connection, authzSummary, nil
}
