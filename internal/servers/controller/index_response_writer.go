package controller

import (
	"bytes"
	"net/http"
)

type indexResponseWriter struct {
	statusCode int
	header     http.Header
	body       *bytes.Buffer
}

// newindexResponseWriter returns an initialized indexResponseWriter
func newIndexResponseWriter() *indexResponseWriter {
	return &indexResponseWriter{
		header: make(http.Header),
		body:   new(bytes.Buffer),
	}
}

func (w *indexResponseWriter) Header() http.Header {
	return w.header
}

func (w *indexResponseWriter) Write(buf []byte) (int, error) {
	return w.body.Write(buf)
}

func (w *indexResponseWriter) WriteHeader(code int) {
	w.statusCode = code
}
