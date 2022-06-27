package session

import (
	"context"
	"sync"

	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
)

// Cache stores session information locally and exposes ways to operate on the
// set of sessions locally in batch.
// This is thread-safe.
type Cache struct {
	controllerSessionConn pbs.SessionServiceClient
	sessionMap            *sync.Map
}

func NewCache(client pbs.SessionServiceClient) *Cache {
	return &Cache{
		controllerSessionConn: client,
		sessionMap:            new(sync.Map),
	}
}

func (m *Cache) Get(id string) *Session {
	if s, ok := m.sessionMap.Load(id); ok {
		return s.(*Session)
	}
	return nil
}

// ForEachSession allows iteration over all the sessions in the cache.
func (m *Cache) ForEachSession(f func(*Session) bool) {
	m.sessionMap.Range(func(_, value any) bool {
		s, ok := value.(*Session)
		if !ok {
			return false
		}
		return f(s)
	})
}

// RefreshSession looks up from the source of truth the session information,
// validates it is valid, and then refreshes the local cache.
func (m *Cache) RefreshSession(ctx context.Context, id string, workerId string) (*Session, error) {
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
	actualSess.ApplyStatus(s.GetStatus())
	return actualSess, nil
}

// DeleteSessionsLocally removes all sessions with the provided id from the
// local cache.  If ids are passed in which do not exist in the local cache
// no error is returned.
func (m *Cache) DeleteSessionsLocally(sessIds []string) {
	for _, s := range sessIds {
		m.sessionMap.Delete(s)
	}
}

func (m *Cache) CloseConnections(ctx context.Context, closeInfo map[string]string) bool {
	return closeConnections(ctx, m.controllerSessionConn, m, closeInfo)
}

// cancelConnections is run by cleanupConnections to iterate over a
// session's connInfoMap and close connections based on the
// connection's state (or regardless if ignoreConnectionState is
// set).
//
// The returned map and slice are the maps of connection -> session,
// and sessions to completely remove from local state, respectively.
func (w *Cache) cancelConnections(connInfoMap map[string]*ConnInfo, ignoreConnectionState bool) []string {
	var closedIds []string
	for k, v := range connInfoMap {
		if v.CloseTime.IsZero() {
			if !ignoreConnectionState && v.Status != pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CLOSED {
				continue
			}

			v.ConnCtxCancelFunc()
			closedIds = append(closedIds, k)
		}
	}

	return closedIds
}
