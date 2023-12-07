// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package controller

import (
	"fmt"
	"math"
	"testing"

	"github.com/hashicorp/boundary/api/targets"
	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/targets/tcp"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/tcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// the default max recv msg size is 4194304, so we're testing that we've
// properly set that to more than the default.  12k of our test targets ==
// 4272262, so it's just big enough and doesn't take too long to populate.
// Locally it takes approx 30s to run this test when creating 12k test targets.
func Test_gatewayDialOptions(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)

	tc := NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	_, proj := iam.TestScopes(t, tc.IamRepo(), iam.WithUserId(token.UserId))

	targetClient := targets.NewClient(client)

	const targetCount = 12000
	for i := 0; i < targetCount; i++ {
		if i != 0 && math.Mod(float64(i), 1000) == 0 {
			t.Logf("created %d targets of %d", i, targetCount)
		}
		_ = tcp.TestTarget(tc.Context(), t, tc.DbConn(), proj.GetPublicId(), fmt.Sprintf("target: %d", i), target.WithAddress("8.8.8.8"))
	}

	res, err := targetClient.List(tc.Context(), proj.GetPublicId())
	require.NoError(err)
	assert.NotEmpty(res)
	assert.Equal(targetCount, len(res.Items))
}
