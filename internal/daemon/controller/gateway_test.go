// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package controller

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/globals"
	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/targets/tcp"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/tcp"
	"github.com/hashicorp/go-uuid"
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

func Test_correlationIdAnnotator(t *testing.T) {
	corId, err := uuid.GenerateUUID()
	require.NoError(t, err)
	req := &http.Request{
		Header: map[string][]string{
			globals.CorrelationIdKey: {corId},
		},
	}

	md := correlationIdAnnotator(context.Background(), req)
	require.NotNil(t, md)
	corIds := md.Get(globals.CorrelationIdKey)
	require.Len(t, corIds, 1)
	assert.Equal(t, corId, corIds[0])

	// Now see if we do not pass a correlation id it generates one
	md = correlationIdAnnotator(context.Background(), &http.Request{})
	require.NotNil(t, md)
	corIds = md.Get(globals.CorrelationIdKey)
	require.Len(t, corIds, 1)
	assert.NotEqual(t, corId, corIds[0])
	// Validate it parses as valid uuid
	_, err = uuid.ParseUUID(corIds[0])
	assert.NoError(t, err)

	// Validate correlationIdAnnotator is case-insensitive
	corId, err = uuid.GenerateUUID()
	require.NoError(t, err)
	req = &http.Request{
		Header: map[string][]string{
			"X-CorReLAtion-id": {corId},
		},
	}
	md = correlationIdAnnotator(context.Background(), req)
	require.NotNil(t, md)
	corIds = md.Get(globals.CorrelationIdKey)
	require.Len(t, corIds, 1)
	assert.Equal(t, corId, corIds[0])
}

func Test_clientAgentHeadersAnnotator(t *testing.T) {
	t.Parallel()
	t.Run("returns metadata with user-agent", func(t *testing.T) {
		t.Parallel()
		req := &http.Request{
			Header: map[string][]string{
				"User-Agent": {"Boundary-client-agent/0.1.4"},
			},
		}
		md := userAgentHeadersAnnotator(context.Background(), req)
		require.NotNil(t, md)
		assert.Equal(t, []string{"Boundary-client-agent/0.1.4"}, md.Get("userAgents"))
	})

	t.Run("returns empty metadata if no user-agent header", func(t *testing.T) {
		t.Parallel()
		req := &http.Request{Header: map[string][]string{}}
		md := userAgentHeadersAnnotator(context.Background(), req)
		assert.Empty(t, md)
	})
}

func Test_WithDisablePathLengthFallback(t *testing.T) {
	ctx := context.Background()
	reqPath := "/v1/example"
	mux := newGrpcGatewayMux()

	assert.NotNil(t, mux)

	err := mux.HandlePath("GET", reqPath, func(w http.ResponseWriter, r *http.Request, pathParams map[string]string) {
		_, _ = fmt.Fprintf(w, "%s", r.Method)
	})
	assert.NoError(t, err)

	err = mux.HandlePath("POST", reqPath, func(w http.ResponseWriter, r *http.Request, pathParams map[string]string) {
		_, _ = fmt.Fprintf(w, "%s", r.Method)
	})
	assert.NoError(t, err)

	r, err := http.NewRequestWithContext(ctx, "POST", reqPath, bytes.NewReader(nil))
	assert.NoError(t, err)

	r.Header.Set("X-HTTP-Method-Override", "GET")
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	body := w.Body.String()
	assert.Equal(t, "POST", body)
}
