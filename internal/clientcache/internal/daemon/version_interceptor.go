// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package daemon

import (
	"fmt"
	"net/http"

	"github.com/hashicorp/boundary/internal/util"
	"github.com/hashicorp/boundary/version"
)

const (
	VersionHeaderKey = "boundary_version"
)

// versionEnforcement is an interceptor which, if the boundary version is included
// in a request, enforces that it matches the version of the daemon currently
// running. If no version is provided, the inteceptor passes the request through.
func versionEnforcement(h http.Handler) http.Handler {
	if util.IsNil(h) {
		return nil
	}

	needVer := version.Get().VersionNumber()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotVer := r.Header.Get(VersionHeaderKey)
		if gotVer != "" && needVer != gotVer {
			writeError(w, fmt.Sprintf("Version mismatch between requester (%q) and daemon (%q). You may need to restart your daemon.", gotVer, needVer), http.StatusBadRequest)
			return
		}
		h.ServeHTTP(w, r)
	})
}
