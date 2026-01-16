// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package worker

import (
	"context"
	"fmt"
	"net/http"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/hashicorp/boundary/internal/daemon/worker/session"
	opsservices "github.com/hashicorp/boundary/internal/gen/ops/services"
	pbhealth "github.com/hashicorp/boundary/internal/gen/worker/health"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/util"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var healthCheckMarshaler = &runtime.JSONPb{
	MarshalOptions: protojson.MarshalOptions{
		// Ensures the json marshaler uses the snake casing as defined in the proto field names.
		UseProtoNames: true,
		// Do not add fields set to zero value to json.
		EmitUnpopulated: false,
	},
	UnmarshalOptions: protojson.UnmarshalOptions{
		// Allows requests to contain unknown fields.
		DiscardUnknown: true,
	},
}

// workerHealthServer is the HealthServer for the worker process. This server
// will always return a 200.
type workerHealthServer struct {
	worker *Worker
	opsservices.UnimplementedHealthServiceServer
}

// GetHealth satisfies the opsservices.HealthServiceServer interface.
// This implementation will always return 200.
func (w workerHealthServer) GetHealth(ctx context.Context, req *opsservices.GetHealthRequest) (*opsservices.GetHealthResponse, error) {
	resp := &opsservices.GetHealthResponse{}
	if req.GetWorkerInfo() {
		resp.WorkerProcessInfo = w.worker.HealthInformation()
	}
	return resp, nil
}

// HealthInformation returns the current worker process health information.
func (w *Worker) HealthInformation() *pbhealth.HealthInfo {
	operationalState := server.UnknownOperationalState
	if v := w.operationalState.Load(); !util.IsNil(v) {
		operationalState = v.(server.OperationalState)
	}

	var upstreamConnectionState connectivity.State
	if v := w.upstreamConnectionState.Load(); !util.IsNil(v) {
		upstreamConnectionState = v.(connectivity.State)
	}

	healthInfo := &pbhealth.HealthInfo{
		State:                   operationalState.String(),
		UpstreamConnectionState: upstreamConnectionState.String(),
	}

	if w.sessionManager == nil {
		// This is assigned in worker Start() which is called prior to the ops
		// listener so this should always be set.  This check is here just to
		// be safe in case that changes.
		return healthInfo
	}

	sessionConns := make(map[string]uint32)
	w.sessionManager.ForEachLocalSession(
		func(s session.Session) bool {
			if connCount := len(s.GetLocalConnections()); connCount > 0 {
				sessionConns[s.GetId()] = uint32(connCount)
			}
			return true
		})
	healthInfo.ActiveSessionCount = wrapperspb.UInt32(uint32(len(sessionConns)))
	healthInfo.SessionConnections = sessionConns
	return healthInfo
}

// GetHealthHandler returns an http.Handler that can be used for handling
// health check requests for just the worker.
func (w *Worker) GetHealthHandler() (http.Handler, error) {
	const op = "worker.(Worker).GetHealthHandler"
	mux := runtime.NewServeMux(
		runtime.WithMarshalerOption(runtime.MIMEWildcard, &runtime.HTTPBodyMarshaler{
			Marshaler: healthCheckMarshaler,
		}))
	err := opsservices.RegisterHealthServiceHandlerServer(w.baseContext, mux, workerHealthServer{worker: w})
	if err != nil {
		return nil, fmt.Errorf("%s: failed to register health service handler: %w", op, err)
	}

	return mux, nil
}
