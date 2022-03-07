package session

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/observability/event"
)

// StateReport is used to report on the state of a Session.
type StateReport struct {
	SessionId     string
	Status        Status
	ConnectionIds []string
}

// WorkerStatusReport is a domain service function that compares the state of
// sessions and connections as reported by a Worker, to the known state in the
// repositories. It returns a []StateReport for each session that is in the
// canceling or terminated state. It also will check for any orphaned
// connections, which is defined as a connection that is in an active state,
// but was not reported by worker. Any orphaned connections will be marked as
// closed.
func WorkerStatusReport(ctx context.Context, repo *Repository, connRepo *ConnectionRepository, workerId string, report []StateReport) ([]StateReport, error) {
	const op = "session.WorkerStatusReport"

	reportedConnections := make([]string, 0)
	reportedSessions := make([]string, 0, len(report))
	for _, r := range report {
		reportedSessions = append(reportedSessions, r.SessionId)
		reportedConnections = append(reportedConnections, r.ConnectionIds...)
	}

	notActive, err := repo.checkIfNoLongerActive(ctx, reportedSessions)
	if err != nil {
		return nil, errors.New(ctx, errors.Internal, op, fmt.Sprintf("Error checking session state for worker %s: %v", workerId, err))
	}

	closed, err := connRepo.closeOrphanedConnections(ctx, workerId, reportedConnections)
	if err != nil {
		return notActive, errors.New(ctx, errors.Internal, op, fmt.Sprintf("Error closing orphaned connections for worker %s: %v", workerId, err))
	}
	if len(closed) > 0 {
		event.WriteSysEvent(ctx, op, "marked unclaimed connections as closed", "server_id", workerId, "count", len(closed))
	}
	return notActive, err
}
