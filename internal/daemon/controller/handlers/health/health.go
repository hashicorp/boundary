package health

import (
	"context"
	"fmt"
	"sync"

	pbs "github.com/hashicorp/boundary/internal/gen/controller/ops/services"
	pbhealth "github.com/hashicorp/boundary/internal/gen/worker/health"
)

type Service struct {
	pbs.UnsafeHealthServiceServer

	workerCountLock sync.Mutex
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
			s.workerCountLock.Lock()
			defer s.workerCountLock.Unlock()
			if s.workerInfo != nil {
				resp.WorkerProcessInfo = s.workerInfo()
			}
		}()
	}

	return resp, nil
}

// ReportCurrentWorkerConnections sets the gauge function that can be used
// to get the current number of active proxy connections the worker is handling.
func (s *Service) ReportCurrentWorkerConnections(fn func() *pbhealth.HealthInfo) error {
	if fn == nil {
		return fmt.Errorf("CurrentWorkerConnection function was nil")
	}
	s.workerCountOnce.Do(func() {
		s.workerInfo = fn
	})
	return nil
}
