// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package daemon

import (
	"net/http"

	"github.com/hashicorp/boundary/internal/util"
	"github.com/hashicorp/boundary/version"
)

const (
	VersionHeaderKey = "boundary_version"
)

// versionInterceptor is an interceptor which attaches the daemon's version
// number to all responses that it intercepts
func versionInterceptor(h http.Handler) http.Handler {
	if util.IsNil(h) {
		return nil
	}

	needVer := version.Get().VersionNumber()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add(VersionHeaderKey, needVer)
		h.ServeHTTP(w, r)
	})
}
