// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package session

import (
	"context"

	"github.com/hashicorp/boundary/internal/errors"
)

// CloseConnections is a domain service function that:
// * closes requested connections
// * uses the sessionId of the connection to see if the session meets conditions for termination
func CloseConnections(ctx context.Context, sessionRepoFn *Repository, connectionRepoFn *ConnectionRepository,
	closeWiths []CloseWith,
) ([]closeConnectionResp, error) {
	const op = "session.AuthorizeConnection"

	closeInfos, err := connectionRepoFn.closeConnections(ctx, closeWiths)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	// Attempt to terminate only once per sessionId
	sessionIdsProcessed := make(map[string]bool)
	for _, c := range closeInfos {
		if !sessionIdsProcessed[c.Connection.SessionId] {
			sessionRepoFn.terminateSessionIfPossible(ctx, c.Connection.SessionId)
			sessionIdsProcessed[c.Connection.SessionId] = true
		}
	}

	return closeInfos, nil
}
