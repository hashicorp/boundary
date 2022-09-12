package health

import (
	"fmt"
	"net/http"
	"sync"

	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/ops/services"
	pbhealth "github.com/hashicorp/boundary/internal/gen/worker/health"
)

type Service struct {
	pbs.UnsafeHealthServiceServer
	replyWithServiceUnavailable bool

	workerCountLock sync.RWMutex
	workerCountOnce sync.Once
	workerInfo      func() *pbhealth.HealthInfo
}

var _ pbs.HealthServiceServer = (*Service)(nil)

func NewService() *Service {
	s := Service{}
	return &s
}

func (s *Service) GetHealth(ctx context.Context, req *pbs.GetHealthRequest) (*pbs.GetHealthResponse, error) {
	resp := &pbs.GetHealthResponse{}

	if req.GetWorkerInfo() {
		func() {
			s.workerCountLock.RLock()
			defer s.workerCountLock.RUnlock()
			if s.workerInfo != nil {
				resp.WorkerProcessInfo = s.workerInfo()
			}
		}()
	}
	if s.replyWithServiceUnavailable {
		err := handlers.SetStatusCode(ctx, http.StatusServiceUnavailable)
		if err != nil {
			return nil, err
		}
	}

	return resp, nil
}

// StartServiceUnavailableReplies gets returned to the caller of NewService.
// When invoked, we start responding to any health queries with a 503.
func (s *Service) StartServiceUnavailableReplies() {
	s.replyWithServiceUnavailable = true
}

// ReportCurrentWorkerConnections sets the gauge function that can be used
// to get the current number of active proxy connections the worker is handling.
func (s *Service) ReportCurrentWorkerConnections(fn func() *pbhealth.HealthInfo) error {
	if fn == nil {
		return fmt.Errorf("CurrentWorkerConnection function was nil")
	}
	s.workerCountLock.Lock()
	defer s.workerCountLock.Unlock()
	s.workerCountOnce.Do(func() {
		s.workerInfo = fn
	})
	return nil
}
