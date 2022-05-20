package targets

import (
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/internal/servers"
	"github.com/hashicorp/boundary/internal/types/scope"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/targets"
	"github.com/hashicorp/go-bexpr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWorkerList_Addresses(t *testing.T) {
	addresses := []string{
		"test1",
		"test2",
		"test3",
		"test4",
	}
	var workerInfos []*pb.WorkerInfo
	var tested workerList
	for _, a := range addresses {
		workerInfos = append(workerInfos, &pb.WorkerInfo{Address: a})
		tested = append(tested, servers.NewWorker(scope.Global.String(),
			servers.WithName(a),
			servers.WithAddress(a)))
	}
	assert.Equal(t, addresses, tested.addresses())
	assert.Equal(t, workerInfos, tested.workerInfos())
}

func TestWorkerList_Filter(t *testing.T) {
	var workers []*servers.Worker
	for i := 0; i < 5; i++ {
		w := servers.NewWorker(scope.Global.String(),
			servers.WithName(fmt.Sprintf("test_worker_%d", i)),
			servers.WithWorkerTags(&servers.Tag{
				Key:   fmt.Sprintf("key%d", i),
				Value: fmt.Sprintf("value%d", i),
			}))
		w.ReportedStatus = servers.NewWorkerStatus("",
			servers.WithName(fmt.Sprintf("config%d", i)),
			servers.WithWorkerTags(&servers.Tag{
				Key: "key",
				// Note that the value is either 0 or 1
				Value: fmt.Sprintf("configvalue%d", i%2),
			}))
		workers = append(workers, w)
	}

	{
		ev, err := bexpr.CreateEvaluator(`"/name" matches "test_worker_[13]" and "configvalue2" in "/tags/key"`)
		require.NoError(t, err)
		got, err := workerList(workers).filtered(ev)
		require.NoError(t, err)
		assert.Len(t, got, 0)
	}
	{
		ev, err := bexpr.CreateEvaluator(`"/name" matches "test_worker_[12]" and "configvalue0" in "/tags/key"`)
		require.NoError(t, err)
		got, err := workerList(workers).filtered(ev)
		require.NoError(t, err)
		assert.Len(t, got, 1)
	}
	{
		ev, err := bexpr.CreateEvaluator(`"configvalue0" in "/tags/key"`)
		require.NoError(t, err)
		got, err := workerList(workers).filtered(ev)
		require.NoError(t, err)
		assert.Len(t, got, 3)
	}
}
