// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package metric

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

func TestInitializeWebsocketCollectors(t *testing.T) {
	// Assert that calling the function with a nil Registerer is a valid operation.
	require.NotPanics(t, func() { InitializeWebsocketCollectors(nil) })

	// Try with an actual Registerer.
	r := prometheus.NewRegistry()
	require.NotPanics(t, func() { InitializeWebsocketCollectors(r) })

	// Expect that some metrics exist.
	f, err := r.Gather()
	require.NoError(t, err)
	require.Greater(t, len(f), 0)
}

func TestWrapProxyHandler(t *testing.T) {
	type rw struct {
		http.ResponseWriter
	}
	type flusher struct {
		http.ResponseWriter
		http.Flusher
	}
	type pusher struct {
		http.ResponseWriter
		http.Pusher
	}
	type flusherPusher struct {
		http.ResponseWriter
		http.Flusher
		http.Pusher
	}

	tests := []struct {
		name        string
		wrap        http.ResponseWriter
		wantFlusher bool
		wantPusher  bool
	}{
		{
			name:        "response writer only",
			wrap:        rw{},
			wantFlusher: false,
			wantPusher:  false,
		},
		{
			name:        "flusher only",
			wrap:        flusher{},
			wantFlusher: true,
			wantPusher:  false,
		},
		{
			name:        "pusher only",
			wrap:        pusher{},
			wantFlusher: false,
			wantPusher:  true,
		},
		{
			name:        "flusher and pusher",
			wrap:        flusherPusher{},
			wantFlusher: true,
			wantPusher:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapped := wrapProxyHandler(&hijackerWrapper{}, tt.wrap)
			require.NotNil(t, wrapped)

			// The wrapped interface should always be a Hijacker and ResponseWriter.
			require.Implements(t, (*http.ResponseWriter)(nil), wrapped)
			require.Implements(t, (*http.Hijacker)(nil), wrapped)

			if tt.wantFlusher {
				require.Implements(t, (*http.Flusher)(nil), wrapped)
			}
			if tt.wantPusher {
				require.Implements(t, (*http.Pusher)(nil), wrapped)
			}
		})
	}
}

func TestHandlerWrapper_WithHijacker(t *testing.T) {
	handlerCalled := false
	h := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { // Mock for the proxy handler.
		handlerCalled = true

		require.NotNil(t, req)
		require.NotNil(t, rw)

		// We only wrap the response writer in metrics code if it implements Hijacker.
		require.IsType(t, &hijackerWrapper{}, rw)

		mw := rw.(*hijackerWrapper)
		require.NotNil(t, mw.Hijacker)
		require.NotNil(t, mw.ResponseWriter)
	})

	rw := &testHttpHijacker{ResponseWriter: httptest.NewRecorder(), t: t}
	req := httptest.NewRequest("GET", "/v1/proxy", nil)
	wrapped := InstrumentWebsocketWrapper(h)
	wrapped.ServeHTTP(rw, req)

	require.True(t, handlerCalled)
}

func TestHandlerWrapper_WithNoHijacker(t *testing.T) {
	handlerCalled := false
	h := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { // Mock for the proxy handler.
		handlerCalled = true

		require.NotNil(t, req)
		require.NotNil(t, rw)
		require.IsType(t, &httptest.ResponseRecorder{}, rw) // The websocket metrics code must not have wrapped `rw`
	})

	rw := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/v1/proxy", nil)
	wrapped := InstrumentWebsocketWrapper(h)
	wrapped.ServeHTTP(rw, req)

	require.True(t, handlerCalled)
}

func TestHijack(t *testing.T) {
	ogConnCount := activeConnCount
	ogBytesReceived := bytesReceived
	ogBytesSent := bytesSent
	t.Cleanup(func() {
		activeConnCount = ogConnCount
		bytesReceived = ogBytesReceived
		bytesSent = ogBytesSent
	})

	tpg := &testPrometheusGauge{t: t}
	activeConnCount = tpg

	tpcBytesRecv := &testPrometheusCounter{t: t}
	bytesReceived = tpcBytesRecv

	tpcBytesSent := &testPrometheusCounter{t: t}
	bytesSent = tpcBytesSent

	underlyingConn := &testConn{t: t, readEOF: true, retWriteLen: true}
	mw := &hijackerWrapper{Hijacker: &testHttpHijacker{t: t, retConn: underlyingConn}}

	c, brw, err := mw.Hijack()
	require.NoError(t, err)
	require.NotNil(t, c)
	require.NotNil(t, brw)

	require.Equal(t, 1, tpg.incCalledN)
	require.Equal(t, 0, tpg.decCalledN)
	require.IsType(t, &wsConn{}, c)

	wsConn := c.(*wsConn)
	require.Equal(t, underlyingConn, wsConn.Conn) // Underlying conn must be our testConn.
	require.Equal(t, &mw.dec, wsConn.Once)        // wsConn.Once must be set to a ptr to `dec`.

	// Assert that the buffer Reader and Writer are backed up
	// by the underlying Conn.
	_, err = io.ReadAll(brw.Reader)
	require.NoError(t, err)
	require.True(t, underlyingConn.readCalled)
	require.True(t, tpcBytesRecv.addCalled)

	_, err = io.WriteString(brw.Writer, "test")
	require.NoError(t, err)
	err = brw.Flush()
	require.NoError(t, err)
	require.True(t, underlyingConn.writeCalled)
	require.True(t, tpcBytesSent.addCalled)
}

func TestHijack_Error(t *testing.T) {
	ogConnCount := activeConnCount
	t.Cleanup(func() { activeConnCount = ogConnCount })

	tpg := &testPrometheusGauge{t: t}
	activeConnCount = tpg

	mw := &hijackerWrapper{
		Hijacker: &testHttpHijacker{
			t:      t,
			retErr: fmt.Errorf("oops!"), // Trigger underlying `Hijack` error
		},
	}

	c, brw, err := mw.Hijack()
	require.Nil(t, c)
	require.Nil(t, brw)
	require.EqualError(t, err, "oops!")

	require.Zero(t, tpg.incCalledN)
	require.Zero(t, tpg.decCalledN)
}

func TestHijack_MultipleCalls(t *testing.T) {
	ogConnCount := activeConnCount
	t.Cleanup(func() { activeConnCount = ogConnCount })

	tpg := &testPrometheusGauge{t: t}
	activeConnCount = tpg

	thh := &testHttpHijacker{t: t, retConn: &testConn{t: t}}
	mw := &hijackerWrapper{Hijacker: thh}

	n := 10
	for i := 0; i < n; i++ {
		_, _, err := mw.Hijack()
		require.NoError(t, err)
	}
	require.Equal(t, n, thh.hijackCalledN)
	require.Equal(t, 1, tpg.incCalledN)
	require.Zero(t, tpg.decCalledN)
}

func TestWsConnRead(t *testing.T) {
	ogBytesReceived := bytesReceived
	t.Cleanup(func() { bytesReceived = ogBytesReceived })

	tpc := &testPrometheusCounter{t: t}
	bytesReceived = tpc

	tc := &testConn{t: t}
	wc := &wsConn{Once: &sync.Once{}, Conn: tc}

	n, err := wc.Read([]byte{})
	require.NoError(t, err)
	require.True(t, tc.readCalled)
	require.True(t, tpc.addCalled)
	require.Equal(t, 1, n)
}

func TestWsConnRead_Error(t *testing.T) {
	ogBytesReceived := bytesReceived
	t.Cleanup(func() { bytesReceived = ogBytesReceived })

	tpc := &testPrometheusCounter{t: t}
	bytesReceived = tpc

	tc := &testConn{t: t, readErr: fmt.Errorf("oops!")} // Trigger underlying `Read` error.
	wc := &wsConn{Once: &sync.Once{}, Conn: tc}

	n, err := wc.Read([]byte{})
	require.EqualError(t, err, "oops!")
	require.True(t, tc.readCalled)
	require.False(t, tpc.addCalled)
	require.Zero(t, n)
}

func TestWsConnWrite(t *testing.T) {
	ogBytesSent := bytesSent
	t.Cleanup(func() { bytesSent = ogBytesSent })

	tpc := &testPrometheusCounter{t: t}
	bytesSent = tpc

	tc := &testConn{t: t}
	wc := &wsConn{Once: &sync.Once{}, Conn: tc}

	n, err := wc.Write([]byte{})
	require.NoError(t, err)
	require.True(t, tc.writeCalled)
	require.True(t, tpc.addCalled)
	require.Equal(t, 1, n)
}

func TestWsConnWrite_Error(t *testing.T) {
	ogBytesSent := bytesSent
	t.Cleanup(func() { bytesSent = ogBytesSent })

	tpc := &testPrometheusCounter{t: t}
	bytesSent = tpc

	tc := &testConn{t: t, writeErr: fmt.Errorf("oops!")} // Trigger underlying `Write` error.
	wc := &wsConn{Once: &sync.Once{}, Conn: tc}

	n, err := wc.Write([]byte{})
	require.EqualError(t, err, "oops!")
	require.True(t, tc.writeCalled)
	require.False(t, tpc.addCalled)
	require.Equal(t, 0, n)
}

func TestWsConnClose(t *testing.T) {
	ogConnCount := activeConnCount
	t.Cleanup(func() { activeConnCount = ogConnCount })

	tpg := &testPrometheusGauge{t: t}
	activeConnCount = tpg

	tc := &testConn{t: t}
	wsConn := &wsConn{Once: &sync.Once{}, Conn: tc}

	err := wsConn.Close()
	require.NoError(t, err)
	require.Equal(t, 1, tc.closeCalledN)
	require.Equal(t, 1, tpg.decCalledN)
	require.Equal(t, 0, tpg.incCalledN)
}

func TestWsConnClose_Error(t *testing.T) {
	ogConnCount := activeConnCount
	t.Cleanup(func() { activeConnCount = ogConnCount })

	tpg := &testPrometheusGauge{t: t}
	activeConnCount = tpg

	wsConn := &wsConn{
		Once: &sync.Once{},
		Conn: &testConn{
			t:        t,
			closeErr: fmt.Errorf("oops!"), // Trigger underlying `Close` error.
		},
	}

	err := wsConn.Close()
	require.EqualError(t, err, "oops!")
}

func TestWsConnClose_MultipleCalls(t *testing.T) {
	ogConnCount := activeConnCount
	t.Cleanup(func() { activeConnCount = ogConnCount })

	tpg := &testPrometheusGauge{t: t}
	activeConnCount = tpg

	tc := &testConn{t: t}
	wsConn := &wsConn{Once: &sync.Once{}, Conn: tc}

	calledCount := 0
	for i := 0; i < 10; i++ {
		wsConn.Close()
		calledCount++
	}

	require.Equal(t, calledCount, tc.closeCalledN)
	require.Equal(t, 1, tpg.decCalledN) // We should only decrement the metric once
	require.Zero(t, tpg.incCalledN)
}

type testHttpHijacker struct {
	// Mocks the underlying http.Hijacker in metricsWrapper.
	http.ResponseWriter
	t             *testing.T
	retConn       net.Conn
	retErr        error
	hijackCalledN int
}

func (h *testHttpHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h.hijackCalledN++

	if h.retErr != nil {
		return nil, nil, h.retErr
	}
	if h.retConn == nil {
		return nil, nil, nil
	}

	brw := bufio.NewReadWriter(bufio.NewReader(h.retConn), bufio.NewWriter(h.retConn))
	return h.retConn, brw, nil
}

type testConn struct {
	// Mocks the underlying net.Conn in wsConn.
	readCalled bool
	readEOF    bool
	readErr    error

	writeCalled bool
	retWriteLen bool
	writeErr    error

	closeCalledN int
	closeErr     error
	t            *testing.T
}

func (tc *testConn) Read(b []byte) (n int, err error) {
	tc.readCalled = true
	if tc.readErr != nil {
		return 0, tc.readErr
	}
	if tc.readEOF { // Simulate an actual read and tx one byte
		b[0] = 1
		return 1, io.EOF
	}

	return 1, nil
}

func (tc *testConn) Write(b []byte) (n int, err error) {
	tc.writeCalled = true
	if tc.writeErr != nil {
		return 0, tc.writeErr
	}
	if tc.retWriteLen {
		return len(b), nil
	}
	return 1, nil
}

func (tc *testConn) Close() error {
	tc.closeCalledN++
	if tc.closeErr != nil {
		return tc.closeErr
	}
	return nil
}
func (tc *testConn) LocalAddr() net.Addr                { return nil } // Unused
func (tc *testConn) RemoteAddr() net.Addr               { return nil } // Unused
func (tc *testConn) SetDeadline(t time.Time) error      { return nil } // Unused
func (tc *testConn) SetReadDeadline(t time.Time) error  { return nil } // Unused
func (tc *testConn) SetWriteDeadline(t time.Time) error { return nil } // Unused

type testPrometheusCounter struct {
	// Mocks a Prometheus Counter as used in Proxy Websocket metrics.
	prometheus.Metric
	prometheus.Collector

	addCalled bool
	t         *testing.T
}

func (tpc *testPrometheusCounter) Inc()        { tpc.t.Fatal("testPrometheusCounter Inc() called") }
func (tpc *testPrometheusCounter) Add(float64) { tpc.addCalled = true }

type testPrometheusGauge struct {
	// Mocks a Prometheus Gauge as used in Proxy Websocket metrics.
	prometheus.Metric
	prometheus.Collector

	incCalledN int
	decCalledN int
	t          *testing.T
}

func (tpg *testPrometheusGauge) Set(float64) { tpg.t.Fatal("testPrometheusGauge Set() called") }
func (tpg *testPrometheusGauge) Inc()        { tpg.incCalledN++ }
func (tpg *testPrometheusGauge) Dec()        { tpg.decCalledN++ }
func (tpg *testPrometheusGauge) Add(float64) { tpg.t.Fatal("testPrometheusGauge Add() called") }
func (tpg *testPrometheusGauge) Sub(float64) { tpg.t.Fatal("testPrometheusGauge Sub() called") }
func (tpg *testPrometheusGauge) SetToCurrentTime() {
	tpg.t.Fatal("testPrometheusGauge SetToCurrentTime() called")
}
