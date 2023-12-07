// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package controller_test

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/daemon/cluster/handlers"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	"github.com/hashicorp/boundary/internal/daemon/worker"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
)

func Test_Controller_RegisterUpstreamMessageServices(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	testCtx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	require.NoError(kmsCache.CreateKeys(context.Background(), scope.Global.String(), kms.WithRandomReader(rand.Reader)))

	logger := hclog.New(&hclog.LoggerOptions{
		Level: hclog.Trace,
	})
	conf, err := config.DevController()
	require.NoError(err)
	c := controller.NewTestController(t, &controller.TestControllerOpts{
		Config: conf,
		Logger: logger.Named("controller"),
	})
	t.Cleanup(c.Shutdown)
	kmsWorker, pkiWorker, _, _ := worker.NewTestMultihopWorkers(t, logger, c.Context(), c.ClusterAddrs(),
		c.Config().WorkerAuthKms, c.Controller().ServersRepoFn, nil, nil, nil, nil)
	t.Cleanup(kmsWorker.Shutdown)
	t.Cleanup(pkiWorker.Shutdown)

	err = handlers.RegisterUpstreamMessageHandler(testCtx, pbs.MsgType_MSG_TYPE_ECHO, &handlers.TestMockUpstreamMessageHandler{})
	require.NoError(err)

	resp, err := pkiWorker.Worker().SendUpstreamMessage(testCtx, &pbs.EchoUpstreamMessageRequest{Msg: "ping"})
	require.NoError(err)

	assert.Empty(cmp.Diff(resp, &pbs.EchoUpstreamMessageResponse{Msg: "ping"}, protocmp.Transform()))
}
