// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/errors"
)

// CreateAppToken will create an apptoken in the repository and return the written apptoken
func (r *Repository) CreateAppToken(ctx context.Context, appToken *AppToken, opt ...Option) (*AppToken, error) {
	const op = "apptoken.(Repository).CreateAppToken"
	if appToken == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing app token")
	}
	if appToken.PublicId != "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "public id is not empty")
	}
	appT := appToken.Clone().(*AppToken)

	opts := getOpts(opt...)

	if opts.withPublicId != "" {
		if !strings.HasPrefix(opts.withPublicId, globals.UserPrefix+"_") {
			return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("passed-in public ID %q has wrong prefix, should be %q", opts.withPublicId, globals.UserPrefix))
		}
		u.PublicId = opts.withPublicId
	} else {
		id, err := newUserId(ctx)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		u.PublicId = id
	}

	// There's no need to use r.lookupUser(...) here, because the new user cannot
	// be associated with any accounts yet.  Why would you typically want to
	// call r.lookupUser(...) here vs returning the create resource?  Well, the
	// created resource doesn't include the user's primary account info (email,
	// full name, etc), since you can't run DML against the view which does
	// provide these output only attributes.  But in this case, there's no way a
	// newly created user could have any accounts, so we don't need to use
	// r.lookupUser(...). I'm adding this comment so a future version of myself
	// doesn't come along and decide to start using r.lookupUser(...) here which
	// would just be an unnecessary database lookup.  You're welcome future me.
	resource, err := r.create(ctx, u)
	if err != nil {
		if errors.IsUniqueError(err) {
			return nil, errors.New(ctx, errors.NotUnique, op, fmt.Sprintf("user %s already exists in org %s", user.Name, user.ScopeId))
		}
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("for %s", u.PublicId)))
	}
	return resource.(*User), nil
}
