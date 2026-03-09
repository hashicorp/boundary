// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

// Response is a custom response that wraps an HTTP response. Body will be
// populated with a buffer containing the response body after Decode is called;
// it will be nil if the response was a 204.
type Response struct {
	resp *http.Response

	Body *bytes.Buffer
	Map  map[string]any
}

// NewResponse returns a new *Response based on the provided http.Response.
// Just as when constructing the Response directly, Body and Map will be
// populated after Decode is called.
func NewResponse(r *http.Response) *Response {
	return &Response{resp: r}
}

// HttpResponse returns the underlying HTTP response
func (r *Response) HttpResponse() *http.Response {
	return r.resp
}

// StatusCode returns the underlying HTTP status code
func (r *Response) StatusCode() int {
	return r.resp.StatusCode
}

func (r *Response) Decode(inStruct any) (*Error, error) {
	if r == nil || r.resp == nil {
		return nil, fmt.Errorf("nil response, cannot decode")
	}
	defer r.resp.Body.Close()

	// Always allocate this buffer. It's okay if the bytes return `nil`.
	r.Body = new(bytes.Buffer)

	if r.resp.StatusCode == 204 {
		// Do nothing.
		return nil, nil
	}

	if r.resp.StatusCode >= 400 {
		// If the status code is >= 400 the body of the response will be the
		// json representation of the Error struct so we decode it as such.
		inStruct = &Error{}
	}

	if r.resp.Body != nil {
		r.Body = new(bytes.Buffer)
		if _, err := r.Body.ReadFrom(r.resp.Body); err != nil {
			return nil, fmt.Errorf("error reading response body: %w", err)
		}

		if r.Body.Len() > 0 {
			reader := bytes.NewReader(r.Body.Bytes())
			dec := json.NewDecoder(reader)
			dec.UseNumber()
			r.Map = make(map[string]any)
			if err := dec.Decode(&r.Map); err != nil {
				return nil, fmt.Errorf("error decoding response to map: %w; response was %s", err, r.Body.String())
			}
			if inStruct != nil {
				reader.Seek(0, 0)
				dec = json.NewDecoder(reader)
				if err := dec.Decode(&inStruct); err != nil {
					return nil, fmt.Errorf("error decoding response to struct: %w; response was %s", err, r.Body.String())
				}
			}
		}
	}

	if r.resp.StatusCode >= 400 {
		apiErr := inStruct.(*Error)
		apiErr.response = r
		return apiErr, nil
	}

	return nil, nil
}
