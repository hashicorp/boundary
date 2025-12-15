// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package cluster

import (
	"context"
	stderror "errors"
	"net"

	"github.com/fatih/structs"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/mitchellh/mapstructure"
	"google.golang.org/protobuf/types/known/structpb"
)

var errStateNotFound = stderror.New("no state attached to the connection")

// WorkerConnectionInfo contains information about a worker that gets attached
// to outgoing connections to an upstream worker or the controller through the
// state of a *protocol.Conn.
type WorkerConnectionInfo struct {
	// The address that the dialing worker is dialing
	UpstreamAddress string `mapstructure:"upstream_address,omitempty"`
	// The worker id of the worker that is dialing
	WorkerId string `mapstructure:"worker_id,omitempty"`
	// The version of the worker that is dialing
	BoundaryVersion string `mapstructure:"boundary_version,omitempty"`
	// The name, used for wrapping registration flow
	Name string `mapstructure:"name,omitempty"`
	// The description, used for wrapping registration flow
	Description string `mapstructure:"description,omitempty"`
	// The public address, used for wrapping registration flow
	PublicAddr string `mapstructure:"public_addr,omitempty"`
	// The operational state, used for wrapping registration flow
	OperationalState string `mapstructure:"operational_state,omitempty"`
}

// AsConnectionStateStruct builds a structPb in the format that is expected for
// workers to attach their state to a *protocol.Conn through the withState option.
func (w *WorkerConnectionInfo) AsConnectionStateStruct() (*structpb.Struct, error) {
	if w == nil {
		return nil, nil
	}
	s := structs.New(w)
	s.TagName = "mapstructure"
	return structpb.NewStruct(s.Map())
}

type stateProvider interface {
	ClientState() *structpb.Struct
}

// GetWorkerInfoFromStateMap returns the WorkerConnectionInfo for the provided
// connection if the connection is a stateProvider.  If it is not a stateProvider
// or if the provided state is nil, an error is returned.
func GetWorkerInfoFromStateMap(ctx context.Context, c net.Conn) (*WorkerConnectionInfo, error) {
	const op = "cluster.GetWorkerInfoFromStateMap"
	var downstreamInfo WorkerConnectionInfo
	pc, ok := c.(stateProvider)
	if !ok {
		return nil, errors.Wrap(ctx, errStateNotFound, op, errors.WithMsg("conn is not a state provider"))
	}
	st := pc.ClientState()
	if st == nil {
		return nil, errors.Wrap(ctx, errStateNotFound, op, errors.WithMsg("no state attached to connection"))
	}
	if err := mapstructure.Decode(st.AsMap(), &downstreamInfo); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return &downstreamInfo, nil
}
