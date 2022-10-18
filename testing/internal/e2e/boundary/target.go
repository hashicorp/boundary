package boundary

import (
	"context"
	"encoding/json"
	"strconv"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/stretchr/testify/require"
)

// CreateNewTargetApi creates a new target in boundary using the go api.
// Returns the id of the new target.
func CreateNewTargetApi(t testing.TB, ctx context.Context, client *api.Client, projectId string, defaultPort string) string {
	tClient := targets.NewClient(client)
	targetPort, err := strconv.ParseInt(defaultPort, 10, 32)
	require.NoError(t, err)
	newTargetResult, err := tClient.Create(ctx, "tcp", projectId,
		targets.WithName("e2e Automated Test Target"),
		targets.WithTcpTargetDefaultPort(uint32(targetPort)),
	)
	require.NoError(t, err)
	newTargetId := newTargetResult.Item.Id
	t.Logf("Created Target: %s", newTargetId)

	return newTargetId
}

// AddHostSourceToTargetApi adds a host source (host set or host) to a target using the go api
func AddHostSourceToTargetApi(t testing.TB, ctx context.Context, client *api.Client, targetId string, hostSourceId string) {
	tClient := targets.NewClient(client)
	_, err := tClient.AddHostSources(ctx, targetId, 0,
		[]string{hostSourceId},
		targets.WithAutomaticVersioning(true),
	)
	require.NoError(t, err)
}

// CreateNewTargetCli creates a new target in boundary using the cli
// Returns the id of the new target.
func CreateNewTargetCli(t testing.TB, projectId string, defaultPort string) string {
	output := e2e.RunCommand(context.Background(), "boundary", "targets", "create", "tcp",
		"-scope-id", projectId,
		"-default-port", defaultPort,
		"-name", "e2e Automated Test Target",
		"-format", "json",
	)
	require.NoError(t, output.Err, string(output.Stderr))
	var newTargetResult targets.TargetCreateResult
	err := json.Unmarshal(output.Stdout, &newTargetResult)
	require.NoError(t, err)
	newTargetId := newTargetResult.Item.Id
	t.Logf("Created Target: %s", newTargetId)

	return newTargetId
}

// AddHostSourceToTargetCli adds a host source (host set or host) to a target using the cli
func AddHostSourceToTargetCli(t testing.TB, targetId string, hostSourceId string) {
	output := e2e.RunCommand(context.Background(), "boundary", "targets", "add-host-sources",
		"-id", targetId,
		"-host-source", hostSourceId,
	)
	require.NoError(t, output.Err, string(output.Stderr))
}
