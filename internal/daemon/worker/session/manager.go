package session

import (
	"context"
	"sync"

	"github.com/hashicorp/boundary/internal/errors"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
)

// Manager stores session information locally and exposes ways to operate on the
// set of sessions locally in batch.
// This is thread-safe.
type Manager struct {
	controllerSessionConn pbs.SessionServiceClient
	sessionMap            *sync.Map
}

// NewManager returns a *Manager which uses the provided ServiceServiceClient to
// perform actions on Sessions and Connections on the Controller.
func NewManager(client pbs.SessionServiceClient) *Manager {
	return &Manager{
		controllerSessionConn: client,
		sessionMap:            new(sync.Map),
	}
}

func (m *Manager) Get(id string) *Session {
	if s, ok := m.sessionMap.Load(id); ok {
		return s.(*Session)
	}
	return nil
}

// ForEachLocalSession calls the provided function with each Session object.
// If the provided function ever returns false the iteration stops.
// If changes to the sessions in the manager happen concurrently, this function
// does not guarantee that the key will or will not be provided in the
// iteration.
func (m *Manager) ForEachLocalSession(f func(*Session) bool) {
	m.sessionMap.Range(func(_, value any) bool {
		s, ok := value.(*Session)
		if !ok {
			return false
		}
		return f(s)
	})
}

// LoadLocalSession looks up from the source of truth the session information,
// validates it is valid, and then refreshes the local manager's data.
// On a local worker, the only value of a Session that we care about that can
// be modified is the Status.  Because of that, if LoadLocalSession is called on
// a Session that is already in the manager's data, only the Status is updated.
func (m *Manager) LoadLocalSession(ctx context.Context, id string, workerId string) (*Session, error) {
	const op = "session.(*Manager).LoadLocalSession"
	switch {
	case id == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "id is not set")
	case workerId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "workerId is not set")
	}

	resp, err := m.controllerSessionConn.LookupSession(ctx, &pbs.LookupSessionRequest{
		SessionId: id,
		WorkerId:  workerId,
	})
	if err != nil {
		return nil, err
	}

	s, err := newSess(m.controllerSessionConn, resp)
	if err != nil {
		return nil, err
	}

	// TODO: Periodically clean this up. We can't rely on things in here but
	// not in cancellation because they could be on the way to being
	// established. However, since cert lifetimes are short, we can simply range
	// through and remove values that are expired.
	actualSessRaw, loaded := m.sessionMap.LoadOrStore(s.GetId(), s)
	if !loaded {
		return s, nil
	}
	// Update the response to the latest
	actualSess := actualSessRaw.(*Session)
	actualSess.ApplyLocalStatus(s.GetStatus())
	return actualSess, nil
}

// DeleteLocalSession removes all sessions with the provided id from the
// local manager.  If ids are passed in which do not exist in the manager
// no error is returned.
func (m *Manager) DeleteLocalSession(sessIds []string) {
	for _, s := range sessIds {
		m.sessionMap.Delete(s)
	}
}

// RequestCloseConnections sends connection close requests to the controller,
// and sets close times within the worker. It should be called during the worker
// status loop and on connection exit on the proxy.
//
// The boolean indicates whether the function was successful, e.g. had any
// errors. Individual events will be sent for the errors if there are any.
//
// closeInfo is a map of connection ids mapped to their individual session ids.
func (m *Manager) RequestCloseConnections(ctx context.Context, closeInfo map[string]string) bool {
	return closeConnections(ctx, m.controllerSessionConn, m, closeInfo)
}
