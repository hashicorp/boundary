package controller

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
)

const magicValue = `{{DEFAULT_ORG_ID}}`

type indexResponseWriter struct {
	statusCode   int
	header       http.Header
	body         *bytes.Buffer
	defaultOrgId string
}

// newindexResponseWriter returns an initialized indexResponseWriter
func newIndexResponseWriter(defaultOrgId string) *indexResponseWriter {
	return &indexResponseWriter{
		header:       make(http.Header),
		body:         new(bytes.Buffer),
		defaultOrgId: defaultOrgId,
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
	newBody := []byte(strings.Replace(i.body.String(), magicValue, i.defaultOrgId, 1))
	w.Header().Set("content-length", fmt.Sprintf("%d", len(newBody)))
	w.WriteHeader(i.statusCode)
	w.Write(newBody)
}
