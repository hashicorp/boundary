// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package daemon

import (
	"net/http"

	"github.com/hashicorp/boundary/internal/util"
	"github.com/hashicorp/boundary/version"
)

const (
	VersionHeaderKey = "boundary_version"
	BackgroundKey    = "background"
)

// serverMetadataInterceptor is an interceptor which attaches the daemon's version
// number to all responses that it intercepts
func serverMetadataInterceptor(h http.Handler, inBackground bool) http.Handler {
	if util.IsNil(h) {
		return nil
	}

	background := "false"
	if inBackground {
		background = "true"
	}
	needVer := version.Get().VersionNumber()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add(BackgroundKey, background)
		w.Header().Add(VersionHeaderKey, needVer)
		h.ServeHTTP(w, r)
	})
}
