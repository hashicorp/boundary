// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package session

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"

	"github.com/hashicorp/boundary/internal/errors"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
)

// CloseCallTimeout is a timeout value
//
// FIXME: This is really ugly -- but not as ugly as plumbing this value into the
// interface. We should figure out something better. For now, it will at least
// keep sync with any changes to the value once it's initialized as the worker
// will set it in its new function; it can also be overridden in tests if
// desired with normal global variable caveats.
var CloseCallTimeout = new(atomic.Int64)

// Manager stores session information locally and exposes ways to operate on the
// set of sessions locally in batch.
// This is thread-safe.
type Manager interface {
	Get(string) Session

	// ForEachLocalSession calls the provided function with each Session object.
	// If the provided function ever returns false the iteration stops.
	// If changes to the sessions in the manager happen concurrently, this function
	// does not guarantee that the key will or will not be provided in the
	// iteration.
	ForEachLocalSession(func(Session) bool)

	// LoadLocalSession looks up from the source of truth the session information,
	// validates it is valid, and then refreshes the local manager's data.
	// On a local worker, the only value of a Session that we care about that can
	// be modified is the Status.  Because of that, if LoadLocalSession is called on
	// a Session that is already in the manager's data, only the Status is updated.
	LoadLocalSession(ctx context.Context, id string, workerId string) (Session, error)

	// DeleteLocalSession removes all sessions with the provided id from the
	// local manager.  If ids are passed in which do not exist in the manager
	// no error is returned.
	DeleteLocalSession([]string)

	// RequestCloseConnections sends connection close requests to the
	// controller, and sets close times within the worker. It should be called
	// during the worker session info loop and on connection exit on the proxy.
	//
	// The boolean indicates whether the function was successful, e.g. had any
	// errors. Individual events will be sent for the errors if there are any.
	//
	// closeInfo is a map of connection ids mapped to connection metadata.
	RequestCloseConnections(context.Context, map[string]*ConnectionCloseData) bool
}

type manager struct {
	controllerSessionConn pbs.SessionServiceClient
	sessionMap            *sync.Map
}

var _ Manager = (*manager)(nil)

// NewManager returns a *Manager which uses the provided ServiceServiceClient to
// perform actions on Sessions and Connections on the Controller.
func NewManager(client pbs.SessionServiceClient) (*manager, error) {
	if isNil(client) {
		return nil, fmt.Errorf("SessionServiceClient is nil")
	}
	return &manager{
		controllerSessionConn: client,
		sessionMap:            new(sync.Map),
	}, nil
}

func (m *manager) Get(id string) Session {
	if s, ok := m.sessionMap.Load(id); ok {
		return s.(*sess)
	}
	return nil
}

func (m *manager) ForEachLocalSession(f func(Session) bool) {
	// TODO: Periodically clean this up. We can't rely on things in here but
	// not in cancellation because they could be on the way to being
	// established. However, since cert lifetimes are short, we can simply range
	// through and remove values that are expired.
	m.sessionMap.Range(func(_, value any) bool {
		s, ok := value.(Session)
		if !ok {
			return false
		}
		return f(s)
	})
}

func (m *manager) LoadLocalSession(ctx context.Context, id string, workerId string) (Session, error) {
	const op = "session.(*manager).LoadLocalSession"
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

	actualSessRaw, loaded := m.sessionMap.LoadOrStore(s.GetId(), s)
	if !loaded {
		return s, nil
	}
	// Update the response to the latest
	actualSess := actualSessRaw.(*sess)
	actualSess.ApplySessionUpdate(s.resp)
	return actualSess, nil
}

func (m *manager) DeleteLocalSession(sessIds []string) {
	for _, s := range sessIds {
		m.sessionMap.Delete(s)
	}
}

func (m *manager) RequestCloseConnections(ctx context.Context, closeInfo map[string]*ConnectionCloseData) bool {
	return closeConnections(ctx, m.controllerSessionConn, m, closeInfo)
}

func isNil(i any) bool {
	if i == nil {
		return true
	}
	switch reflect.TypeOf(i).Kind() {
	case reflect.Ptr, reflect.Map, reflect.Array, reflect.Chan, reflect.Slice:
		return reflect.ValueOf(i).IsNil()
	}
	return false
}
