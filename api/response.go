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

	// TODO Remove as we'll use the common err format for this
	if r.resp.StatusCode == 403 {
		// Nothing to be done
		return &Error{
			Status:  http.StatusForbidden,
			Message: "Forbidden",
		}, nil
	}

	apiErr := &Error{
		Status: int32(r.resp.StatusCode),
	}
	if r.resp.Body != nil {
		r.Body = new(bytes.Buffer)
		if _, err := r.Body.ReadFrom(r.resp.Body); err != nil {
			return nil, fmt.Errorf("error reading response body: %w", err)
		}

		if r.Body.Len() != 0 {
			dec := json.NewDecoder(bytes.NewReader(r.Body.Bytes()))
			if r.resp.StatusCode >= 400 {
				inStruct = apiErr
			}
			if inStruct != nil {
				if err := dec.Decode(inStruct); err != nil {
					return nil, fmt.Errorf("error decoding response: %w; response was %s", err, r.Body.String())
				}
			}
		}
	}
	if r.resp.StatusCode >= 400 {
		return apiErr, nil
	}

	return nil, nil
}
