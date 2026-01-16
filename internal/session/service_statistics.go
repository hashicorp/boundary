// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package session

import (
	"context"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/event"
)

// CloseOrphanedConnections closes the orphaned connections for a given worker.
func CloseOrphanedConnections(ctx context.Context, repo *ConnectionRepository, workerId string, connections []*Connection) ([]string, error) {
	const op = "session.CloseOrphanedConnections"
	if repo == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing connection repository")
	}
	if workerId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing worker id")
	}
	connectionIds := []string{}
	for _, c := range connections {
		connectionIds = append(connectionIds, c.GetPublicId())
	}
	closed, err := repo.closeOrphanedConnections(ctx, workerId, connectionIds)
	if len(closed) > 0 {
		event.WriteSysEvent(ctx, op, "marked unclaimed connections as closed", "worker_id", workerId, "count", len(closed))
	}
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("failed to close orphaned connections for worker %q", workerId))
	}
	return closed, nil
}

// UpdateConnectionBytesUpDown processes the connection statistics for a given worker.
func UpdateConnectionBytesUpDown(ctx context.Context, repo *ConnectionRepository, connections []*Connection) error {
	const op = "session.UpdateConnectionBytesUpDown"
	if repo == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing connection repository")
	}
	err := repo.updateBytesUpBytesDown(ctx, connections...)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("failed to update bytes up and down for worker connection statistics"))
	}
	return nil
}
