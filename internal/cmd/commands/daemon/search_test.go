// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"testing"

	"github.com/hashicorp/boundary/api/targets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSearchTargetsRequest(t *testing.T) {
	ctx := context.Background()

	socketListener, err := listen(ctx)

	require.NoError(t, err)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/search/targets", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, r.Header.Get("token_name"), "default")
		assert.Equal(t, r.Header.Get("boundary_addr"), "default")
		b, err := json.Marshal(map[string]interface{}{"Items": []*targets.Target{
			{Id: "ttcp_1", Name: "target name 1"},
			{Id: "ttcp_2", Name: "target name 1"},
		}})
		require.NoError(t, err)
		_, err = w.Write(b)
		require.NoError(t, err)
	})
	srv := &http.Server{
		Handler: mux,
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		srv.Serve(socketListener)
	}()

	fb := targetFilterBy{
		tokenName:    "default",
		boundaryAddr: "default",
	}

	got, err := searchTargets(ctx, fb, false)
	require.NoError(t, err)
	got.Body = new(bytes.Buffer)
	_, err = got.Body.ReadFrom(got.HttpResponse().Body)
	require.NoError(t, err)

	type itemsResp struct {
		Items []*targets.Target `json:"Items"`
	}

	var items itemsResp
	require.NoError(t, json.Unmarshal(got.Body.Bytes(), &items), "got error when parsing", got.Body.String())
	assert.Len(t, items.Items, 2)
	require.NoError(t, srv.Close())
	wg.Wait()
}
