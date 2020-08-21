package worker

import (
	"crypto/tls"
	"errors"
)

func (w *Worker) getJobTls(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	var jobId string
	switch len(hello.SupportedProtos) {
	case 1:
		if hello.SupportedProtos[0] == "h2" {
			// In the future we'll handle it when we support custom certs,
			// but for now we don't support this.
			return nil, errors.New("h2 is not currently a supported alpn nextproto value")
		} else {
			jobId = hello.SupportedProtos[0]
		}
	default:
		return nil, errors.New("too many alpn nextproto values")
	}

	_ = jobId
	return nil, nil
}
