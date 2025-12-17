// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package server

import "github.com/hashicorp/boundary/internal/server/store"

// Controller is a server that is responsible for understanding configuration,
// authenticating and authorizing users, and serving user API requests (e.g. to
// initiate a session). They also assign tasks to workers (session handling,
// session recording parsing, etc.).
type Controller struct {
	*store.Controller
}

// NewController returns a new controller. Valid options are WithAddress and WithDescription.
// All other options are ignored.
func NewController(privateId string, opt ...Option) *Controller {
	opts := GetOpts(opt...)
	controller := &Controller{
		Controller: &store.Controller{
			PrivateId:   privateId,
			Address:     opts.withAddress,
			Description: opts.withDescription,
		},
	}

	return controller
}
