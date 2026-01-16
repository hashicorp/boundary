// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package requests

import (
	"context"

	"github.com/hashicorp/boundary/internal/perms"
)

// ContextRequestInforation is a type used solely for context keys -- see the
// variable below
type ContextRequestInformation struct{}

// ContextRequestInformationKey is a value to keep linters from complaining
// about clashing identifiers
var ContextRequestInformationKey ContextRequestInformation

// RequestContext is used to propagate request information. It can be updated at
// various points, e.g. UserId would be updated via the result of auth.Verify.
//
// It serves as a struct to gather information we learn about the request as it
// goes along. This is distinct from options handling; none of the fields here
// are "optional" and should all eventually be populated as the request moves
// through the system.
type RequestContext struct {
	// Method is the method of the request
	Method string

	// Path is the path of the request
	Path string

	// UserId contains the final discovered user ID
	UserId string

	// OutputFields is the set of fields authorized for output for the
	// authorized action, if not the default
	OutputFields *perms.OutputFields
}

// NewRequestContext returns a derived context with a new RequestContext value
// added in.
func NewRequestContext(parent context.Context, opt ...Option) context.Context {
	opts := getOpts(opt...)
	ret := &RequestContext{
		UserId: opts.withUserId,
	}
	return context.WithValue(parent, ContextRequestInformationKey, ret)
}

// RequestContextFromCtx pulls out RequestContext and returns it and an
// indication it was found. If it's not found, nil will be returned and the bool
// will be false.
func RequestContextFromCtx(ctx context.Context) (*RequestContext, bool) {
	reqCtxRaw := ctx.Value(ContextRequestInformationKey)
	if reqCtxRaw == nil {
		return nil, false
	}
	reqCtx, ok := reqCtxRaw.(*RequestContext)
	if !ok {
		return nil, false
	}
	return reqCtx, true
}

// OutputFields returns output fields from the given context and calls
// SelfOrDefaults on it. If the context does not contain a RequestContext,
// this will return nil, false.
func OutputFields(ctx context.Context) (*perms.OutputFields, bool) {
	reqCtx, ok := RequestContextFromCtx(ctx)
	if !ok {
		return nil, false
	}
	return reqCtx.OutputFields.SelfOrDefaults(reqCtx.UserId), true
}
