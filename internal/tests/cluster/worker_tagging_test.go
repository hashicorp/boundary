// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package cluster

import (
	"testing"

	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	ct "github.com/hashicorp/boundary/internal/daemon/controller/handlers/targets"
	"github.com/hashicorp/boundary/internal/daemon/worker"
	"github.com/hashicorp/boundary/internal/tests/helper"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/targets"
	"github.com/hashicorp/go-hclog"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestWorkerTagging(t *testing.T) {
	logger := hclog.New(&hclog.LoggerOptions{
		Level: hclog.Trace,
	})

	conf, err := config.DevController()
	require.NoError(t, err)

	c1 := controller.NewTestController(t, &controller.TestControllerOpts{
		Config:                 conf,
		InitialResourcesSuffix: "1234567890",
		Logger:                 logger.Named("c1"),
	})
	defer c1.Shutdown()

	ctx := c1.Context()

	// No workers yet
	helper.ExpectWorkers(t, c1)

	// Ensure target is valid
	client := c1.Client()
	client.SetToken(c1.Token().Token)
	tcl := targets.NewClient(client)
	tgt, err := tcl.Read(ctx, "ttcp_1234567890")
	require.NoError(t, err)
	require.NotNil(t, tgt)

	// Worker 1
	conf, err = config.DevWorker()
	require.NoError(t, err)
	conf.Worker.Name = "test_worker_1"
	conf.Worker.Tags = map[string][]string{
		"region": {"east"},
		"foo":    {"bar"},
	}
	w1 := worker.NewTestWorker(t, &worker.TestWorkerOpts{
		Config:           conf,
		WorkerAuthKms:    c1.Config().WorkerAuthKms,
		InitialUpstreams: c1.ClusterAddrs(),
		Logger:           logger.Named("w1"),
	})
	defer w1.Shutdown()
	w1Addr := w1.ProxyAddrs()[0]
	w1.Worker().WaitForNextSuccessfulStatusUpdate()

	// Worker 2
	conf, err = config.DevWorker()
	require.NoError(t, err)
	conf.Worker.Name = "test_worker_2"
	conf.Worker.Tags = map[string][]string{
		"region": {"west"},
		"az":     {"one", "two", "three"},
	}
	w2 := worker.NewTestWorker(t, &worker.TestWorkerOpts{
		Config:           conf,
		WorkerAuthKms:    c1.Config().WorkerAuthKms,
		InitialUpstreams: c1.ClusterAddrs(),
		Logger:           logger.Named("w2"),
	})
	defer w2.Shutdown()
	w2Addr := w2.ProxyAddrs()[0]
	w2.Worker().WaitForNextSuccessfulStatusUpdate()

	// Worker 3
	conf, err = config.DevWorker()
	require.NoError(t, err)
	conf.Worker.Name = "test_worker_3"
	conf.Worker.Tags = map[string][]string{
		"region": {"west"},
		"az":     {"one", "three"},
	}
	w3 := worker.NewTestWorker(t, &worker.TestWorkerOpts{
		Config:           conf,
		WorkerAuthKms:    c1.Config().WorkerAuthKms,
		InitialUpstreams: c1.ClusterAddrs(),
		Logger:           logger.Named("w3"),
	})
	defer w3.Shutdown()
	w3Addr := w3.ProxyAddrs()[0]

	w3.Worker().WaitForNextSuccessfulStatusUpdate()

	helper.ExpectWorkers(t, c1, w1, w2, w3)

	// Ensure we are using the OSS filter, which uses egress only for worker selection
	oldAuthFun := ct.AuthorizeSessionWorkerFilterFn
	ct.AuthorizeSessionWorkerFilterFn = ct.AuthorizeSessionWithWorkerFilter
	validateIngressFn := ct.ValidateIngressWorkerFilterFn
	ct.ValidateIngressWorkerFilterFn = ct.IngressWorkerFilterUnsupported

	cases := []struct {
		name          string
		egressFilter  string
		ingressFilter string
		expWorkers    []string
		wantErr       bool
	}{
		{
			name:       "base case",
			expWorkers: []string{w1Addr, w2Addr, w3Addr},
		},
		{
			name:         "name and region",
			egressFilter: `"/name" matches "test_worker_[13]" and "west" in "/tags/region"`,
			expWorkers:   []string{w3Addr},
		},
		{
			name:         "name and az",
			egressFilter: `"/name" matches "test_worker_[23]" and "three" in "/tags/az"`,
			expWorkers:   []string{w2Addr, w3Addr},
		},
		{
			name:         "key not found doesn't error",
			egressFilter: `"bar" in "/tags/foo"`,
			expWorkers:   []string{w1Addr},
		},
		{
			name:          "ingress filter invalid",
			ingressFilter: `"/name" matches "test_worker_[13]" and "west" in "/tags/region"`,
			expWorkers:    []string{w3Addr},
			wantErr:       true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)

			opts := []targets.Option{targets.WithAutomaticVersioning(true), targets.WithDescription(tc.name)}
			if tc.egressFilter != "" {
				opts = append(opts, targets.WithEgressWorkerFilter(tc.egressFilter))
			}
			if tc.ingressFilter != "" {
				opts = append(opts, targets.WithIngressWorkerFilter(tc.ingressFilter))
			}
			tgt, err := tcl.Update(ctx, "ttcp_1234567890", 0, opts...)
			if tc.wantErr {
				require.Error(err)
				return
			}
			require.NoError(err)
			require.NotNil(tgt)

			// Fetch the session and decode the token
			sar, err := tcl.AuthorizeSession(ctx, "ttcp_1234567890")
			require.NoError(err)
			sat := sar.GetItem().(*targets.SessionAuthorization).AuthorizationToken
			decodedSat, err := base58.FastBase58Decoding(sat)
			require.NoError(err)
			var sad pb.SessionAuthorizationData
			require.NoError(proto.Unmarshal(decodedSat, &sad))

			var addrs []string
			for _, worker := range sad.GetWorkerInfo() {
				addrs = append(addrs, worker.GetAddress())
			}
			assert.ElementsMatch(tc.expWorkers, addrs)
		})
	}
	ct.AuthorizeSessionWorkerFilterFn = oldAuthFun
	ct.ValidateIngressWorkerFilterFn = validateIngressFn
}
