// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package health

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	pbs "github.com/hashicorp/boundary/internal/gen/ops/services"
	pbhealth "github.com/hashicorp/boundary/internal/gen/worker/health"
)

type Service struct {
	pbs.UnsafeHealthServiceServer
	replyWithServiceUnavailable bool

	workerInfoLock sync.RWMutex
	workerInfoOnce sync.Once
	workerInfoFn   func() *pbhealth.HealthInfo
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
			s.workerInfoLock.RLock()
			defer s.workerInfoLock.RUnlock()
			if s.workerInfoFn != nil {
				resp.WorkerProcessInfo = s.workerInfoFn()
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

// SetWorkerProcessInformationFunc sets the function that can be used to get the
// current worker related process information.
func (s *Service) SetWorkerProcessInformationFunc(fn func() *pbhealth.HealthInfo) error {
	if fn == nil {
		return fmt.Errorf("CurrentWorkerConnection function was nil")
	}
	s.workerInfoLock.Lock()
	defer s.workerInfoLock.Unlock()
	s.workerInfoOnce.Do(func() {
		s.workerInfoFn = fn
	})
	return nil
}
