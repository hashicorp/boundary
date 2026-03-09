// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package targets

import (
	"testing"

	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/types/scope"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/targets"
	"github.com/stretchr/testify/assert"
)

func TestWorkerList_Addresses(t *testing.T) {
	addresses := []string{
		"test1",
		"test2",
		"test3",
		"test4",
	}
	var workerInfos []*pb.WorkerInfo
	var tested server.WorkerList
	for _, a := range addresses {
		workerInfos = append(workerInfos, &pb.WorkerInfo{Address: a})
		tested = append(tested, server.NewWorker(scope.Global.String(),
			server.WithName(a),
			server.WithAddress(a)))
	}
	assert.Equal(t, addresses, tested.Addresses())
	assert.Equal(t, workerInfos, tested.WorkerInfos())
}
