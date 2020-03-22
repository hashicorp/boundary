package controller

import "crypto/tls"

func (c Controller) validateWorkerTLS(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	return nil, nil
}
