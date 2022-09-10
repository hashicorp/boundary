package worker

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/hashicorp/boundary/internal/daemon/worker/session"
	pbhealth "github.com/hashicorp/boundary/internal/gen/worker/health"
	"github.com/hashicorp/boundary/internal/observability/event"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var healthCheckMarshaler = &runtime.JSONPb{
	MarshalOptions: protojson.MarshalOptions{EmitUnpopulated: true},
}

// HealthInformation returns the current worker process health information.
func (w *Worker) HealthInformation() *pbhealth.HealthInfo {
	if w.sessionManager == nil {
		// This is assigned in worker Start() which is called prior to the ops
		// listener so this should always be set.  This check is here just to
		// be safe in case that changes.
		return &pbhealth.HealthInfo{}
	}
	// TODO(toddknight): Attach the worker's current state.
	sessionConns := make(map[string]uint32)
	w.sessionManager.ForEachLocalSession(
		func(s session.Session) bool {
			if connCount := len(s.GetLocalConnections()); connCount > 0 {
				sessionConns[s.GetId()] = uint32(connCount)
			}
			return true
		})
	return &pbhealth.HealthInfo{
		ActiveSessionCount: wrapperspb.UInt32(uint32(len(sessionConns))),
		SessionConnections: sessionConns,
	}
}

// HealthHandler returns an http.Handler that can be used for handling
// health check requests for just the worker.  The worker will always
// return healthy as long as the process is running
func (w *Worker) HealthHandler() http.Handler {
	const op = "worker.(Worker).HealthHandler"
	return http.HandlerFunc(func(wr http.ResponseWriter, r *http.Request) {
		// Set the Cache-Control header for all responses returned
		wr.Header().Set("Cache-Control", "no-store")
		const (
			workerInfoQueryParam = "worker_info"
			workerProcessInfoKey = "worker_process_info"
		)
		ctx := r.Context()
		if r.Method != http.MethodGet {
			wr.WriteHeader(http.StatusMethodNotAllowed)
			event.WriteError(ctx, op, fmt.Errorf("received a non get request method"))
			return
		}
		respJson := make(map[string]*pbhealth.HealthInfo)
		if s := r.URL.Query().Get(workerInfoQueryParam); s == "1" || strings.EqualFold(s, "true") {
			respJson[workerProcessInfoKey] = w.HealthInformation()
		}
		b, err := healthCheckMarshaler.Marshal(respJson)
		if err != nil {
			wr.WriteHeader(http.StatusInternalServerError)
			event.WriteError(ctx, op, err, event.WithInfoMsg("unable to marshal health endpoint json"))
			return
		}

		wr.Header().Add("Content-Type", "application/json")
		wr.Write(b)
	})
}
