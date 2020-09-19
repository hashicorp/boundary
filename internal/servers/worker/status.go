package worker

import (
	"context"
	"math/rand"
	"time"

	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/boundary/internal/servers"
	"github.com/hashicorp/boundary/internal/types/resource"
	"google.golang.org/grpc/resolver"
)

// In the future we could make this configurable
const (
	statusInterval = 2 * time.Second
)

type LastStatusInformation struct {
	*pbs.StatusResponse
	StatusTime time.Time
}

func (w *Worker) startStatusTicking(cancelCtx context.Context) {
	go func() {
		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		// This function exists to desynchronize calls to controllers from
		// workers so we aren't always getting status updates at the exact same
		// intervals, to ease the load on the DB.
		getRandomInterval := func() time.Duration {
			// 0 to 0.5 adjustment to the base
			f := r.Float64() / 2
			// Half a chance to be faster, not slower
			if r.Float32() > 0.5 {
				f = -1 * f
			}
			return statusInterval + time.Duration(f*float64(time.Second))
		}

		timer := time.NewTimer(0)
		for {
			select {
			case <-cancelCtx.Done():
				w.logger.Info("status ticking shutting down")
				return

			case <-timer.C:
				var activeJobs []*pbs.JobStatus
				w.sessionInfoMap.Range(func(key, value interface{}) bool {
					var jobInfo pbs.SessionJobInfo
					sessionId := key.(string)
					si := value.(*sessionInfo)
					si.RLock()
					connections := make([]*pbs.Connection, 0, len(si.connInfoMap))
					for k, v := range si.connInfoMap {
						connections = append(connections, &pbs.Connection{
							ConnectionId: k,
							Status:       v.status,
						})
					}
					jobInfo.SessionId = sessionId
					activeJobs = append(activeJobs, &pbs.JobStatus{
						Job: &pbs.Job{
							Type: pbs.JOBTYPE_JOBTYPE_SESSION,
							JobInfo: &pbs.Job_SessionInfo{
								SessionInfo: &pbs.SessionJobInfo{
									SessionId:   sessionId,
									Status:      si.status,
									Connections: connections,
								},
							},
						},
					})
					return true
				})
				client := w.controllerStatusConn.Load().(pbs.ServerCoordinationServiceClient)
				result, err := client.Status(cancelCtx, &pbs.StatusRequest{
					Jobs: activeJobs,
					Worker: &servers.Server{
						PrivateId:   w.conf.RawConfig.Worker.Name,
						Name:        w.conf.RawConfig.Worker.Name,
						Type:        resource.Worker.String(),
						Description: w.conf.RawConfig.Worker.Description,
						Address:     w.listeningAddress,
					},
				})
				if err != nil {
					w.logger.Error("error making status request to controller", "error", err)
				} else {
					w.logger.Trace("successfully sent status to controller")
					addrs := make([]resolver.Address, 0, len(result.Controllers))
					strAddrs := make([]string, 0, len(result.Controllers))
					for _, v := range result.Controllers {
						addrs = append(addrs, resolver.Address{Addr: v.Address})
						strAddrs = append(strAddrs, v.Address)
					}
					w.Resolver().UpdateState(resolver.State{Addresses: addrs})
					w.logger.Trace("found controllers", "addresses", strAddrs)
					w.lastStatusSuccess.Store(&LastStatusInformation{StatusResponse: result, StatusTime: time.Now()})

					for _, request := range result.GetJobsRequests() {
						switch request.GetRequestType() {
						case pbs.CHANGETYPE_CHANGETYPE_UPDATE_STATE,
							pbs.CHANGETYPE_CHANGETYPE_CANCEL:
							switch request.GetJob().GetType() {
							case pbs.JOBTYPE_JOBTYPE_SESSION:
								sessInfo := request.GetJob().GetSessionInfo()
								sessionId := sessInfo.GetSessionId()
								siRaw, ok := w.sessionInfoMap.Load(sessionId)
								if !ok {
									w.logger.Warn("asked to cancel session but could not find a local information for it", "session_id", sessionId)
									continue
								}
								si := siRaw.(*sessionInfo)
								si.Lock()
								si.status = sessInfo.GetStatus()
								if request.GetRequestType() == pbs.CHANGETYPE_CHANGETYPE_CANCEL {
									for k, v := range si.connInfoMap {
										v.connCancel()
										w.logger.Info("terminated connection", "session_id", sessionId, "connection_id", k)
										v.status = pbs.CONNECTIONSTATUS_CONNECTIONSTATUS_CLOSED
									}
								}
								si.Unlock()
							}
						}
					}
				}
				timer.Reset(getRandomInterval())
			}
		}
	}()
}

func (w *Worker) LastStatusSuccess() *LastStatusInformation {
	return w.lastStatusSuccess.Load().(*LastStatusInformation)
}
