// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package metric

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"sync"

	"github.com/hashicorp/boundary/globals"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	proxyWebsocketSubsystem = "worker_proxy_websocket"
)

var (
	activeConnCount = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: globals.MetricNamespace,
			Subsystem: proxyWebsocketSubsystem,
			Name:      "active_connections",
			Help:      "Count of open websocket proxy connections (to Boundary workers).",
		},
	)

	bytesReceived = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: globals.MetricNamespace,
			Subsystem: proxyWebsocketSubsystem,
			Name:      "received_bytes_total",
			Help:      "Count of received bytes for Worker proxy websocket connections.",
		},
	)

	bytesSent = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: globals.MetricNamespace,
			Subsystem: proxyWebsocketSubsystem,
			Name:      "sent_bytes_total",
			Help:      "Count of sent bytes for Worker proxy websocket connections.",
		},
	)
)

// InitializeWebsocketCollectors registers the websocket collectors onto `r`.
// It panics upon the first registration that causes an error.
func InitializeWebsocketCollectors(r prometheus.Registerer) {
	if r == nil {
		return
	}
	r.MustRegister(activeConnCount, bytesReceived, bytesSent)
}

// InstrumentWebsocketWrapper expects an http.Handler where websockets are used
// and wraps it to instrument that websocket with metrics (bytes received, sent, etc).
func InstrumentWebsocketWrapper(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		nextRw := rw
		if rwh, ok := rw.(http.Hijacker); ok {
			nextRw = wrapProxyHandler(&hijackerWrapper{ResponseWriter: rw, Hijacker: rwh}, rw)
		}
		next.ServeHTTP(nextRw, req)
	})
}

// wrapProxyHandler wraps the incoming `http.ResponseWriter` in `hijackerWrapper` such
// that we don't lose access to the other possible implementations that could be present
// in the original object.
//
// See: https://medium.com/@cep21/interface-wrapping-method-erasure-c523b3549912
func wrapProxyHandler(with *hijackerWrapper, wrap http.ResponseWriter) http.ResponseWriter {
	const op = "metric.wrapProxyHandler"
	flusher, _ := wrap.(http.Flusher)
	pusher, _ := wrap.(http.Pusher)

	// We don't check for http.Hijacker because hijackerWrapper is always an http.Hijacker.
	switch {
	case flusher == nil && pusher == nil:
		return with
	case flusher != nil && pusher == nil:
		return struct {
			*hijackerWrapper
			http.Flusher
		}{with, flusher}
	case flusher == nil && pusher != nil:
		return struct {
			*hijackerWrapper
			http.Pusher
		}{with, pusher}
	default:
		return struct {
			*hijackerWrapper
			http.Flusher
			http.Pusher
		}{with, flusher, pusher}
	}
}

type wsConn struct {
	*sync.Once
	net.Conn
}

func (wc *wsConn) Read(b []byte) (int, error) {
	n, err := wc.Conn.Read(b)
	if err != nil && err != io.EOF {
		return n, err
	}
	bytesReceived.Add(float64(n))
	return n, err
}

func (wc *wsConn) Write(b []byte) (int, error) {
	n, err := wc.Conn.Write(b)
	if err != nil {
		return n, err
	}
	bytesSent.Add(float64(n))
	return n, nil
}

func (wc *wsConn) Close() error {
	wc.Once.Do(func() { activeConnCount.Dec() })
	return wc.Conn.Close()
}

type hijackerWrapper struct {
	// The `Once` objects constrain incrementing/decrementing active connections.
	// Only a precautionary measure as:
	// 1. http.(Hijacker).Hijack() cannot be called more than once (2nd call is an error).
	// 2. websocket.(*Conn).Close() cannot be called more than once (2nd call is no-op).
	inc sync.Once
	dec sync.Once

	// `ServeHTTP` takes an `http.ResponseWriter`, so `metricsWrapper`
	// needs to implement it. Other than that, `ResponseWriter` is unused.
	http.ResponseWriter

	http.Hijacker
}

func (hw *hijackerWrapper) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	c, rw, err := hw.Hijacker.Hijack()
	if err != nil {
		return nil, nil, err
	}
	c = &wsConn{Conn: c, Once: &hw.dec}

	// Our underlying `Hijack` call returns a `bufio.ReadWriter` object with the
	// `Reader` and `Writer` set to the `net.Conn` object *before* we wrap it.
	// The websocket library uses this buffer to Read and Write. This means
	// our Conn implementation would never be called if we didn't replace the
	// `Reader` and `Writer`.
	buffered, _ := rw.Reader.Peek(rw.Reader.Buffered())
	rw.Reader.Reset(io.MultiReader(bytes.NewReader(buffered), c))
	rw = bufio.NewReadWriter(rw.Reader, bufio.NewWriter(c))

	hw.inc.Do(func() { activeConnCount.Inc() })
	return c, rw, err
}
