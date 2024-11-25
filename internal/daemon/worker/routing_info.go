// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package worker

import (
	"context"
	"fmt"
	"math/rand"
	"slices"
	"time"

	"github.com/hashicorp/boundary/internal/daemon/worker/common"
	"github.com/hashicorp/boundary/internal/event"
	pb "github.com/hashicorp/boundary/internal/gen/controller/servers"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/sdk/pbs/plugin"
)

type LastRoutingInfo struct {
	*pbs.RoutingInfoResponse
	RoutingInfoTime         time.Time
	LastCalculatedUpstreams []string
}

// LastRoutingInfoSuccess reports the last time we sent a successful
// session route info request.
func (w *Worker) LastRoutingInfoSuccess() *LastRoutingInfo {
	s, ok := w.lastRoutingInfoSuccess.Load().(*LastRoutingInfo)
	if !ok {
		return nil
	}
	return s
}

func (w *Worker) startRoutingInfoTicking(cancelCtx context.Context) {
	const op = "worker.(Worker).startRoutingInfoTicking"
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	timer := time.NewTimer(0)
	for {
		select {
		case <-cancelCtx.Done():
			event.WriteSysEvent(w.baseContext, op, "session route info ticking shutting down")
			return

		case <-timer.C:
			w.sendRoutingInfo(cancelCtx)
			// Add a bit of jitter to the wait, so we aren't always getting,
			// status updates at the exact same intervals, to ease the load on the DB.
			timer.Reset(common.RoutingInfoInterval + getRandomInterval(r))
		}
	}
}

func (w *Worker) sendRoutingInfo(cancelCtx context.Context) {
	const op = "worker.(Worker).sendRoutingInfo"
	w.confLock.Lock()
	defer w.confLock.Unlock()

	var storageBucketCredentialStates map[string]*plugin.StorageBucketCredentialState
	if w.RecordingStorage != nil {
		storageBucketCredentialStates = w.RecordingStorage.GetStorageBucketCredentialStates()
		// If the local storage state is unknown, and we have recording storage set, get the state from the recording storage
		// and set it on the worker. This is done once to ensure that the worker has the correct state for the first status
		// call.
		if w.localStorageState.Load() == server.UnknownLocalStorageState {
			w.localStorageState.Store(w.RecordingStorage.GetLocalStorageState(cancelCtx))
		}
	}

	var tags []*pb.TagPair
	// If we're not going to request a tag update, no reason to have these
	// marshaled on every status call.
	if w.updateTags.Load() {
		tags = w.tags.Load().([]*pb.TagPair)
	}
	connectionState := w.downstreamConnManager.Connected()

	ctx, cancel := context.WithTimeout(cancelCtx, time.Duration(w.routingInfoCallTimeoutDuration.Load()))
	defer cancel()
	clientCon := w.GrpcClientConn.Load()
	client := pbs.NewServerCoordinationServiceClient(clientCon)
	result, err := client.RoutingInfo(ctx, &pbs.RoutingInfoRequest{
		WorkerId:                              w.LastStatusSuccess().WorkerId,
		ConnectedUnmappedWorkerKeyIdentifiers: connectionState.UnmappedKeyIds(),
		ConnectedWorkerPublicIds:              connectionState.WorkerIds(),
		LocalStorageState:                     w.localStorageState.Load().(server.LocalStorageState).String(),
		OperationalState:                      w.operationalState.Load().(server.OperationalState).String(),
		StorageBucketCredentialStates:         storageBucketCredentialStates,
		Tags:                                  tags,
		UpdateTags:                            w.updateTags.Load(),
	})
	if err != nil {
		event.WriteError(cancelCtx, op, err, event.WithInfoMsg("error making session route info request to controller", "controller_address", clientCon.Target()))
		return
	}

	if authorized := result.GetAuthorizedDownstreamWorkers(); authorized != nil {
		connectionState.DisconnectMissingWorkers(authorized.GetWorkerPublicIds())
		connectionState.DisconnectMissingUnmappedKeyIds(authorized.GetUnmappedWorkerKeyIdentifiers())
	}
	var addrs []string
	// This may be empty if we are in a multiple hop scenario
	if len(result.CalculatedUpstreams) > 0 {
		addrs = make([]string, 0, len(result.CalculatedUpstreams))
		for _, v := range result.CalculatedUpstreams {
			addrs = append(addrs, v.Address)
		}
	} else if checkHCPBUpstreams != nil && checkHCPBUpstreams(w) {
		// This is a worker that is one hop away from managed workers, so attempt to get that list
		hcpbWorkersCtx, hcpbWorkersCancel := context.WithTimeout(cancelCtx, time.Duration(w.statusCallTimeoutDuration.Load()))
		defer hcpbWorkersCancel()
		workersResp, err := client.ListHcpbWorkers(hcpbWorkersCtx, &pbs.ListHcpbWorkersRequest{})
		if err != nil {
			event.WriteError(hcpbWorkersCtx, op, err, event.WithInfoMsg("error fetching managed worker information"))
		} else {
			addrs = make([]string, 0, len(workersResp.Workers))
			for _, v := range workersResp.Workers {
				addrs = append(addrs, v.Address)
			}
		}
	}
	if len(addrs) == 0 {
		addrs = append(addrs, w.conf.RawConfig.Worker.InitialUpstreams...)
	}
	w.updateAddresses(cancelCtx, addrs)

	// Store the new route info after updating the addresses so that it can compare to the old route info first
	w.lastRoutingInfoSuccess.Store(&LastRoutingInfo{RoutingInfoResponse: result, RoutingInfoTime: time.Now(), LastCalculatedUpstreams: addrs})
}

// Update address receivers and dialing listeners with new addrs
func (w *Worker) updateAddresses(cancelCtx context.Context, addrs []string) {
	const op = "worker.(Worker).updateAddrs"

	if len(addrs) == 0 {
		return
	}

	lastRouteInfo := w.lastRoutingInfoSuccess.Load().(*LastRoutingInfo)
	// Compare upstreams; update resolver if there is a difference, and emit an event with old and new addresses
	if lastRouteInfo != nil && !slices.Equal(lastRouteInfo.LastCalculatedUpstreams, addrs) {
		upstreamsMessage := fmt.Sprintf("Upstreams has changed; old upstreams were: %s, new upstreams are: %s", lastRouteInfo.LastCalculatedUpstreams, addrs)
		event.WriteSysEvent(cancelCtx, op, upstreamsMessage)
		for _, as := range w.addressReceivers {
			as.SetAddresses(addrs)
		}
	} else if lastRouteInfo == nil {
		for _, as := range w.addressReceivers {
			as.SetAddresses(addrs)
		}
		event.WriteSysEvent(cancelCtx, op, fmt.Sprintf("Upstreams after first status set to: %s", addrs))
	}

	// regardless of whether or not it's a new address, we need to set
	// them for secondary connections
	for _, as := range w.addressReceivers {
		switch {
		case as.Type() == secondaryConnectionReceiverType:
			as.SetAddresses(slices.Clone(addrs))
		}
	}
}
