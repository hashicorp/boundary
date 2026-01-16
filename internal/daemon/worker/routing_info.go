// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package worker

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"slices"
	"time"

	"github.com/hashicorp/boundary/internal/event"
	pb "github.com/hashicorp/boundary/internal/gen/controller/servers"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/hashicorp/boundary/version"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"google.golang.org/grpc/connectivity"
)

var firstRoutingInfoCheckPostHooks = []func(context.Context, *Worker) error{
	// Start session route info and statistics ticking after first routing info success
	func(ctx context.Context, w *Worker) error {
		w.tickerWg.Add(2)
		go func() {
			defer w.tickerWg.Done()
			w.startSessionInfoTicking(w.baseContext)
		}()
		go func() {
			defer w.tickerWg.Done()
			w.startStatisticsTicking(w.baseContext)
		}()
		return nil
	},
}

var downstreamWorkersFactory func(ctx context.Context, workerId string, ver string) (graph, error)

var checkHCPBUpstreams func(w *Worker) bool

// LastRoutingInfo represents the last successful routing info sent to the controller.
type LastRoutingInfo struct {
	*pbs.RoutingInfoResponse
	RoutingInfoTime         time.Time
	LastCalculatedUpstreams []string
}

// WaitForNextSuccessfulRoutingInfoUpdate waits for the next successful routing info. It's
// used by testing in place of a more opaque and
// possibly unnecessarily long sleep for things like initial controller
// check-in, etc.
//
// The timeout is aligned with the worker's routing info grace period. A nil error
// means the routing info was sent successfully.
func (w *Worker) WaitForNextSuccessfulRoutingInfoUpdate() error {
	const op = "worker.(Worker).WaitForNextSuccessfulRoutingInfoUpdate"
	waitStart := time.Now()
	ctx, cancel := context.WithTimeout(w.baseContext, time.Duration(w.successfulRoutingInfoGracePeriod.Load()))
	defer cancel()
	event.WriteSysEvent(ctx, op, "waiting for next routing info report to controller")
	for {
		select {
		case <-time.After(time.Second):
			// pass

		case <-ctx.Done():
			event.WriteError(ctx, op, ctx.Err(), event.WithInfoMsg("error waiting for next routing info report to controller"))
			return ctx.Err()
		}

		if w.lastSuccessfulRoutingInfoTime().After(waitStart) {
			break
		}
	}

	event.WriteSysEvent(ctx, op, "next worker routing info update sent successfully")
	return nil
}

func (w *Worker) startRoutingInfoTicking(cancelCtx context.Context) {
	const op = "worker.(Worker).startRoutingInfoTicking"
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	timer := time.NewTimer(0)
	for {
		select {
		case <-cancelCtx.Done():
			event.WriteSysEvent(w.baseContext, op, "RoutingInfo ticking shutting down")
			return

		case <-timer.C:
			// If we've never managed to successfully authenticate then we won't have
			// any session information anyways and this will produce a ton of noise in
			// observability, so skip calling the function and retry in a short duration
			if w.everAuthenticated.Load() == authenticationStatusNeverAuthenticated {
				timer.Reset(10 * time.Millisecond)
				continue
			}

			w.sendWorkerRoutingInfo(cancelCtx)
			// Desynchronize calls to controllers from workers, so we aren't always
			// getting RoutingInfo updates at the exact same intervals, to ease the load on the DB.
			timer.Reset(w.routingInfoInterval + getRandomInterval(r))
		}
	}
}

// LastRoutingInfoSuccess reports the last time we sent a successful
// RoutingInfo request.
func (w *Worker) LastRoutingInfoSuccess() *LastRoutingInfo {
	s, ok := w.lastRoutingInfoSuccess.Load().(*LastRoutingInfo)
	if !ok || s == nil {
		return nil
	}
	// make a deep copy to avoid race conditions from accessing underlying data
	copied := *s
	return &copied
}

func (w *Worker) sendWorkerRoutingInfo(cancelCtx context.Context) {
	const op = "worker.(Worker).sendWorkerRoutingInfo"
	// Lock access to w.conf and w.addressReceivers
	w.confAddressReceiversLock.Lock()
	defer w.confAddressReceiversLock.Unlock()

	clientCon := w.GrpcClientConn.Load()
	// Send RoutingInfo information
	client := pbs.NewServerCoordinationServiceClient(clientCon)
	var tags []*pb.TagPair
	// If we're not going to request a tag update, no reason to have these
	// marshaled on every RoutingInfo call.
	if w.updateTags.Load() {
		tags = w.tags.Load().([]*pb.TagPair)
	}
	ctx, cancel := context.WithTimeout(cancelCtx, time.Duration(w.routingInfoCallTimeoutDuration.Load()))
	defer cancel()

	keyId := w.WorkerAuthCurrentKeyId.Load()
	switch {
	case w.conf.RawConfig.Worker.Name == "" && keyId == "":
		event.WriteError(cancelCtx, op, errors.New("worker name and keyId are both empty; at least one is needed to identify a worker"),
			event.WithInfoMsg("error making RoutingInfo request to controller"))
	}

	var storageBucketCredentialStates map[string]*plugin.StorageBucketCredentialState
	if w.RecordingStorage != nil {
		storageBucketCredentialStates = w.RecordingStorage.GetStorageBucketCredentialStates()
		// If the local storage state is unknown, and we have recording storage set, get the state from the recording storage
		// and set it on the worker. This is done once to ensure that the worker has the correct state for the first RoutingInfo
		// call.
		if w.localStorageState.Load() == server.UnknownLocalStorageState {
			w.localStorageState.Store(w.RecordingStorage.GetLocalStorageState(cancelCtx))
		}
	}
	versionInfo := version.Get()
	connectionState := w.downstreamConnManager.Connected()
	result, err := client.RoutingInfo(ctx, &pbs.RoutingInfoRequest{
		WorkerStatus: &pb.ServerWorkerStatus{
			Name:                          w.conf.RawConfig.Worker.Name,
			Description:                   w.conf.RawConfig.Worker.Description,
			Address:                       w.conf.RawConfig.Worker.PublicAddr,
			Tags:                          tags,
			KeyId:                         keyId,
			ReleaseVersion:                versionInfo.FullVersionNumber(false),
			OperationalState:              w.operationalState.Load().(server.OperationalState).String(),
			LocalStorageState:             w.localStorageState.Load().(server.LocalStorageState).String(),
			StorageBucketCredentialStates: storageBucketCredentialStates,
		},
		ConnectedUnmappedWorkerKeyIdentifiers: connectionState.UnmappedKeyIds(),
		ConnectedWorkerPublicIds:              connectionState.WorkerIds(),
		UpdateTags:                            w.updateTags.Load(),
	})
	if err != nil {
		event.WriteError(cancelCtx, op, err, event.WithInfoMsg("error making routing info request to controller", "controller_address", clientCon.Target()))

		// In the case that the control plane has gone down and come up with different IPs,
		// append initial upstreams/ cluster addr to the resolver to try
		if pastGrace, _, _ := w.isPastGrace(); pastGrace && w.GrpcClientConn.Load().GetState() == connectivity.TransientFailure {
			routingInfo := w.lastRoutingInfoSuccess.Load().(*LastRoutingInfo)
			// make a deep copy to avoid race conditions from accessing underlying data
			// since routingInfo may be modified later in this function
			copied := *routingInfo
			lastRoutingInfo := &copied
			if lastRoutingInfo != nil && lastRoutingInfo.LastCalculatedUpstreams != nil {
				addrs := lastRoutingInfo.LastCalculatedUpstreams

				if len(w.conf.RawConfig.Worker.InitialUpstreams) > 0 {
					addrs = append(addrs, w.conf.RawConfig.Worker.InitialUpstreams...)
				} else if HandleHcpbClusterId != nil && len(w.conf.RawConfig.HcpbClusterId) > 0 {
					clusterId, err := parseutil.ParsePath(w.conf.RawConfig.HcpbClusterId)
					if err != nil && !errors.Is(err, parseutil.ErrNotAUrl) {
						event.WriteError(cancelCtx, op, err, event.WithInfoMsg("failed to parse HCP Boundary cluster ID"))
					} else {
						clusterAddress := HandleHcpbClusterId(clusterId)
						addrs = append(addrs, clusterAddress)
					}
				}

				slices.Sort(addrs)
				addrs = slices.Compact(addrs)
				if slices.Equal(lastRoutingInfo.LastCalculatedUpstreams, addrs) {
					// Nothing to update
					return
				}

				w.updateAddresses(cancelCtx, addrs)
				lastRoutingInfo.LastCalculatedUpstreams = addrs
				w.lastRoutingInfoSuccess.Store(lastRoutingInfo)
			}
		}
		return
	}

	w.updateTags.Store(false)

	if authorized := result.GetAuthorizedDownstreamWorkers(); authorized != nil {
		connectionState.DisconnectMissingWorkers(authorized.GetWorkerPublicIds())
		connectionState.DisconnectMissingUnmappedKeyIds(authorized.GetUnmappedWorkerKeyIdentifiers())
	}
	var addrs []string
	// This may be empty if we are in a multiple hop scenario
	if len(result.GetCalculatedUpstreamAddresses()) > 0 {
		addrs = result.GetCalculatedUpstreamAddresses()
	} else if checkHCPBUpstreams != nil && checkHCPBUpstreams(w) {
		// This is a worker that is one hop away from managed workers, so attempt to get that list
		hcpbWorkersCtx, hcpbWorkersCancel := context.WithTimeout(cancelCtx, time.Duration(w.routingInfoCallTimeoutDuration.Load()))
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

	w.updateAddresses(cancelCtx, addrs)

	w.lastRoutingInfoSuccess.Store(&LastRoutingInfo{RoutingInfoResponse: result, RoutingInfoTime: time.Now(), LastCalculatedUpstreams: addrs})

	// If we have post hooks for after the first RoutingInfo check, run them now
	if w.everAuthenticated.CompareAndSwap(authenticationStatusFirstAuthentication, authenticationStatusFirstRoutingInfoRpcSuccessful) {
		if downstreamWorkersFactory != nil {
			downstreamWorkers, err := downstreamWorkersFactory(cancelCtx, w.LastRoutingInfoSuccess().WorkerId, versionInfo.FullVersionNumber(false))
			if err != nil {
				event.WriteError(cancelCtx, op, err)
				w.conf.ServerSideShutdownCh <- struct{}{}
				return
			}
			w.downstreamWorkers.Store(&graphContainer{graph: downstreamWorkers})
		}
		for _, fn := range firstRoutingInfoCheckPostHooks {
			if err := fn(cancelCtx, w); err != nil {
				// If we can't verify status we can't be expected to behave
				// properly so error and trigger shutdown
				event.WriteError(cancelCtx, op, fmt.Errorf("error running first routing info check post hook: %w", err))
				// We don't use a non-blocking select here to ensure that it
				// happens; we should catch blocks in tests but we want to
				// ensure the signal is being listened to
				w.conf.ServerSideShutdownCh <- struct{}{}
				return
			}
		}
	}
}

func (w *Worker) lastSuccessfulRoutingInfoTime() time.Time {
	lastRoutingInfo := w.LastRoutingInfoSuccess()
	if lastRoutingInfo == nil {
		return w.workerStartTime
	}

	return lastRoutingInfo.RoutingInfoTime
}

// Update address receivers and dialing listeners with new addrs
func (w *Worker) updateAddresses(cancelCtx context.Context, addrs []string) {
	const op = "worker.(Worker).updateAddresses"

	if len(addrs) > 0 {
		lastRoutingInfo := w.lastRoutingInfoSuccess.Load().(*LastRoutingInfo)
		// Compare upstreams; update resolver if there is a difference, and emit an event with old and new addresses
		if lastRoutingInfo != nil && !strutil.EquivalentSlices(lastRoutingInfo.LastCalculatedUpstreams, addrs) {
			upstreamsMessage := fmt.Sprintf("Upstreams has changed; old upstreams were: %s, new upstreams are: %s", lastRoutingInfo.LastCalculatedUpstreams, addrs)
			event.WriteSysEvent(cancelCtx, op, upstreamsMessage)
			for _, as := range w.addressReceivers {
				as.SetAddresses(addrs)
			}
		} else if lastRoutingInfo == nil {
			for _, as := range w.addressReceivers {
				as.SetAddresses(addrs)
			}
			event.WriteSysEvent(cancelCtx, op, fmt.Sprintf("Upstreams after first RoutingInfo set to: %s", addrs))
		}
	}

	// regardless of whether or not it's a new address, we need to set
	// them for secondary connections
	for _, as := range w.addressReceivers {
		switch {
		case as.Type() == secondaryConnectionReceiverType:
			tmpAddrs := make([]string, len(addrs))
			copy(tmpAddrs, addrs)
			if len(tmpAddrs) == 0 {
				tmpAddrs = append(tmpAddrs, w.conf.RawConfig.Worker.InitialUpstreams...)
			}
			as.SetAddresses(tmpAddrs)
		}
	}
}

func (w *Worker) isPastGrace() (bool, time.Time, time.Duration) {
	t := w.lastSuccessfulRoutingInfoTime()
	u := time.Duration(w.successfulRoutingInfoGracePeriod.Load())
	v := time.Since(t)
	return v > u, t, u
}

// getRandomInterval returns a random duration between -0.5 and 0.5 seconds (exclusive).
func getRandomInterval(r *rand.Rand) time.Duration {
	// 0 to 0.5 adjustment to the base
	f := r.Float64() / 2
	// Half a chance to be faster, not slower
	if r.Float32() > 0.5 {
		f = -1 * f
	}
	return time.Duration(f * float64(time.Second))
}
