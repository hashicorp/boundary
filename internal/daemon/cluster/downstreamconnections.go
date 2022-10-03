package cluster

import (
	"net"
	"sync"
)

// DownstreamManager associates downstream worker ids with the connections to
// a specific server.
// It is safe to access DownstreamManager concurrently.
type DownstreamManager struct {
	workerConnections map[string][]net.Conn
	l                 sync.RWMutex
}

func NewDownstreamManager() *DownstreamManager {
	return &DownstreamManager{
		workerConnections: make(map[string][]net.Conn),
	}
}

// addConnection adds a connection associated with the provided downstream id.
func (m *DownstreamManager) addConnection(id string, c net.Conn) {
	m.l.Lock()
	defer m.l.Unlock()
	m.workerConnections[id] = append(m.workerConnections[id], c)
}

// disconnect disconnects all connections associated with the provided worker key id.
func (m *DownstreamManager) Disconnect(id string) {
	m.l.Lock()
	defer m.l.Unlock()
	for _, c := range m.workerConnections[id] {
		c.Close()
	}
	delete(m.workerConnections, id)
}

// Connected returns a struct which can report its
func (m *DownstreamManager) Connected() []string {
	m.l.RLock()
	defer m.l.RUnlock()
	var r []string
	for k, v := range m.workerConnections {
		if len(v) > 0 {
			r = append(r, k)
		}
	}
	return r
}

// DisconnectUnauthorized calls disconnects for all ids which are
// present in the connected but not in the authorized slice of key ids.
func DisconnectUnauthorized(dm *DownstreamManager, connected, authorized []string) {
	am := make(map[string]struct{}, len(authorized))
	for _, i := range authorized {
		am[i] = struct{}{}
	}
	for _, i := range connected {
		if _, found := am[i]; !found {
			dm.Disconnect(i)
		}
	}
}
