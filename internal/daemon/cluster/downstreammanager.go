// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cluster

import (
	"net"
	"sync"
)

// DownstreamManager associates downstream worker key identifiers with the
// connections to  a specific server.
// It is safe to access DownstreamManager concurrently.
type DownstreamManager struct {
	keyToWorkerId    map[string]string
	workerIdToKeyIds map[string]map[string]struct{}

	// maps a key id to a connection initiated by a downstream worker
	workerConnections map[string][]net.Conn
	l                 sync.RWMutex
}

func NewDownstreamManager() *DownstreamManager {
	return &DownstreamManager{
		workerConnections: make(map[string][]net.Conn),
		keyToWorkerId:     make(map[string]string),
		workerIdToKeyIds:  make(map[string]map[string]struct{}),
	}
}

func (m *DownstreamManager) mapKeyToWorkerId(keyId, wId string) {
	m.l.Lock()
	defer m.l.Unlock()
	m.keyToWorkerId[keyId] = wId
	if _, ok := m.workerIdToKeyIds[wId]; !ok {
		m.workerIdToKeyIds[wId] = make(map[string]struct{})
	}
	m.workerIdToKeyIds[wId][keyId] = struct{}{}
}

// addConnection adds a connection associated with the provided downstream
// worker key identifier.
func (m *DownstreamManager) addConnection(id string, c net.Conn) {
	m.l.Lock()
	defer m.l.Unlock()
	m.workerConnections[id] = append(m.workerConnections[id], c)
}

// disconnectWorkerId closes all connections associated with the provided
// worker public id
func (m *DownstreamManager) disconnectWorkerId(id string) {
	m.l.Lock()
	defer m.l.Unlock()
	for k := range m.workerIdToKeyIds[id] {
		for _, c := range m.workerConnections[k] {
			c.Close()
		}
		delete(m.workerConnections, k)
		delete(m.keyToWorkerId, k)
	}
	delete(m.workerIdToKeyIds, id)
}

// disconnectKeys closes all connections associated with the provided worker key
// identifier.
func (m *DownstreamManager) disconnectKeys(id string) {
	m.l.Lock()
	defer m.l.Unlock()
	for _, c := range m.workerConnections[id] {
		c.Close()
	}
	delete(m.workerConnections, id)

	// clean up all the associations between worker id and key ids
	if wId, ok := m.keyToWorkerId[id]; ok {
		delete(m.keyToWorkerId, id)
		delete(m.workerIdToKeyIds[wId], id)
		if len(m.workerIdToKeyIds[wId]) == 0 {
			delete(m.workerIdToKeyIds, wId)
		}
	}
}

// Connected returns a connected state which provides the worker ids that are
// being tracked and any key ids for which we don't know the worker id.
func (m *DownstreamManager) Connected() *connectedState {
	m.l.RLock()
	defer m.l.RUnlock()
	seenWIds := make(map[string]struct{})
	var workerIds, keyIds []string
	for k, v := range m.workerConnections {
		if len(v) > 0 {
			if w, ok := m.keyToWorkerId[k]; ok {
				if _, ok := seenWIds[w]; !ok {
					seenWIds[w] = struct{}{}
					workerIds = append(workerIds, w)
				}
			} else {
				keyIds = append(keyIds, k)
			}
		}
	}
	return &connectedState{
		dm:             m,
		unmappedKeyIds: keyIds,
		workerIds:      workerIds,
	}
}

// connectedState provides a state of the downstream manager and allows users
// to request connections be disconnected that are capturred in this state.
type connectedState struct {
	dm             *DownstreamManager
	unmappedKeyIds []string
	workerIds      []string
}

// UnMappedKeyIds are the key ids for which no worker id association is known
// and which are tracking at least 1 connection.
func (s *connectedState) UnMappedKeyIds() []string {
	return s.unmappedKeyIds
}

// WorkerIds are the public ids for workers which we are tracking connections.
func (s *connectedState) WorkerIds() []string {
	return s.workerIds
}

// DisconnectMissingWorkers disconnects all workers that are not in the slice
// of worker ids provided but are tracked in this connected state.
func (s *connectedState) DisconnectMissingWorkers(workers []string) {
	aw := make(map[string]struct{}, len(workers))
	for _, i := range workers {
		aw[i] = struct{}{}
	}
	for _, w := range s.workerIds {
		if _, found := aw[w]; !found {
			s.dm.disconnectWorkerId(w)
		}
	}
}

// DisconnectMissingKeyIds disconnects all workers which are not in the slice of
// key ids provided but are tracked in this connected state.
func (s *connectedState) DisconnectMissingKeyIds(keyIds []string) {
	am := make(map[string]struct{}, len(keyIds))
	for _, i := range keyIds {
		am[i] = struct{}{}
	}
	for _, i := range s.unmappedKeyIds {
		if _, found := am[i]; !found {
			s.dm.disconnectKeys(i)
		}
	}
}
