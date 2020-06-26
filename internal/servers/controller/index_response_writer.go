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

func (i *indexResponseWriter) Header() http.Header {
	return i.header
}

func (i *indexResponseWriter) Write(buf []byte) (int, error) {
	return i.body.Write(buf)
}

func (i *indexResponseWriter) WriteHeader(code int) {
	i.statusCode = code
}

func (i *indexResponseWriter) writeToWriter(w http.ResponseWriter) {
	for k, v := range i.header {
		for _, h := range v {
			w.Header().Add(k, h)
		}
	}
	w.WriteHeader(i.statusCode)
	w.Write(i.body.Bytes())
}
