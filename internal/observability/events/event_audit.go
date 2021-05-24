package event

// fields are intentionally alphabetically ordered so they will match output
// from marshaling event json
type Audit struct {
	Id      Id     `json:"id,omitempty"`
	Op      Op     `json:"op,omitempty"`
	Version string `json:"version"`
	Type    string `json:"type"`

	RequestInfo *RequestInfo `json:"request_info,omitempty"`
}
