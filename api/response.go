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
}

// HttpResponse returns the underlying HTTP response
func (r *Response) HttpResponse() *http.Response {
	return r.resp
}

func (r *Response) Decode(inStruct interface{}) (*Error, error) {
	if r == nil || r.resp == nil {
		return nil, fmt.Errorf("nil response, cannot decode")
	}
	defer r.resp.Body.Close()

	if r.resp.StatusCode == 204 {
		// Do nothing.
		return nil, nil
	}

	if inStruct == nil {
		return nil, fmt.Errorf("nil value given to decode into and not a 204 response")
	}

	r.Body = new(bytes.Buffer)
	if _, err := r.Body.ReadFrom(r.resp.Body); err != nil {
		return nil, fmt.Errorf("error reading response body: %w", err)
	}

	dec := json.NewDecoder(bytes.NewReader(r.Body.Bytes()))
	var apiErr Error
	if r.resp.StatusCode >= 400 {
		inStruct = &apiErr
	}
	if err := dec.Decode(inStruct); err != nil {
		return nil, fmt.Errorf("error decoding response: %w", err)
	}
	if r.resp.StatusCode >= 400 {
		return &apiErr, nil
	}

	return nil, nil
}
