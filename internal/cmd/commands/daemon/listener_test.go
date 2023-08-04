// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package daemon

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListenDialCommunication(t *testing.T) {
	ctx := context.Background()

	payload := "Hello test"

	socketListener, err := listener(ctx)

	require.NoError(t, err)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/test", func(w http.ResponseWriter, r *http.Request) {
		_, err = fmt.Fprint(w, payload)
		require.NoError(t, err)
	})
	srv := &http.Server{
		Handler: mux,
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		assert.ErrorIs(t, srv.Serve(socketListener), http.ErrServerClosed)
	}()

	client, err := api.NewClient(nil)
	require.NoError(t, err)
	addr, err := socketAddress()
	require.NoError(t, err)
	require.NoError(t, client.SetAddr(addr))
	client.SetToken("")
	req, err := client.NewRequest(ctx, "GET", "/test", nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	assert.NoError(t, err)
	got, err := io.ReadAll(resp.HttpResponse().Body)
	require.NoError(t, err)
	assert.Equal(t, string(got), payload)

	require.NoError(t, srv.Close())
	wg.Wait()
}
