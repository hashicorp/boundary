// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package auth

import (
	"context"

	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"google.golang.org/protobuf/types/known/structpb"
)

// CalculateAuthorizedCollectionActions returns authorized actions for the given
// inputs.
//
// NOTE: Eventually we should unit test this, but for now every service handler
// is validating the results of this (as it was pulled out of the service
// handlers).
func CalculateAuthorizedCollectionActions(ctx context.Context,
	authResults VerifyResults,
	mapToRange map[resource.Type]action.ActionSet,
	scopeId, pin string,
) (map[string]*structpb.ListValue, error) {
	res := &perms.Resource{
		ScopeId: scopeId,
		Pin:     pin,
	}
	// Range over the defined collections and check permissions against those
	// collections.
	var ret map[string]*structpb.ListValue
	for k, v := range mapToRange {
		res.Type = k
		acts := authResults.FetchActionSetForType(ctx, k, v, WithResource(res)).Strings()
		if len(acts) > 0 {
			if ret == nil {
				ret = make(map[string]*structpb.ListValue)
			}
			lv, err := structpb.NewList(strutil.StringListToInterfaceList(acts))
			if err != nil {
				return nil, err
			}
			ret[k.PluralString()] = lv
		}
	}
	return ret, nil
}
