// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

// Package listtoken encapsulates domain logic surrounding
// list endpoint tokens. List tokens are used when users
// paginate through results in our list endpoints, and also to
// allow users to request new, updated and deleted resources.
package listtoken

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/boundary/internal/boundary"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/types/resource"
)

// A Token is returned in list endpoints for the purposes of pagination.
// A Token has a subtype, which defines which stage in the list pagination
// lifecycle is in place. The transitions between subtypes can be seen as
// a state machine with the following diagram:
//
//	     ,---------------------.
//	     |   Initial Request   |
//	     `---------------------'
//	      *         *
//	     /          | More pages in initial phase
//	    /           |
//	   |      ,---------------------.
//	   |      |   PaginationToken   | *-. More results in this page
//	   |      `---------------------' <-'
//	   |                 *
//	   | No more results | End of initial pagination phase
//	   |                 |
//	,----------------------.
//	|  StartRefreshToken   | *-. End of refresh phase
//	`----------------------' <-'
//	    *                ^
//	    | More results   | End of refresh phase
//	    |                *
//	 ,--------------------.
//	 |    RefreshToken    | *-. More result in this page
//	 `--------------------' <-'
//
// For more information, please consult ICU-110
type Token struct {
	// The create time of the token. Constant for the lifetime
	// of the token.
	CreateTime time.Time
	// The resource type of the list endpoint this token
	// is associated with. Constant for the lifetime
	// of the token.
	ResourceType resource.Type
	// A hash of the grants of the user who made the original
	// request. Only used to ensure that grants have not changed
	// between requests. Constant for the lifetime of
	// the token.
	GrantsHash []byte
	// The specific subtype of this token. Always
	// set ot either PaginationToken, StartRefreshToken
	// or RefreshToken.
	Subtype TokenSubtype
}

// TokenSubtype is used to create a discriminated union of types
// that can be used as a subtype for a list token.
type TokenSubtype interface {
	isTokenSubtype()
}

// Pagination token represents a pagination token subtype to a list
// token. It is used during the initial pagination phase.
type PaginationToken struct {
	// The ID of the last item on the previous page.
	LastItemId string
	// The create time of the last item on the previous page.
	LastItemCreateTime time.Time
}

func (*PaginationToken) isTokenSubtype() {}

// StartRefreshToken represents the transition between two phases,
// either the initial pagination phase and the first refresh phase,
// or between refresh phases.
type StartRefreshToken struct {
	// The end time of the phase previous to this one,
	// which should be used as the lower bound for the
	// new refresh phase.
	PreviousPhaseUpperBound time.Time
	// The timestamp of the transaction that last listed the deleted IDs,
	// for use as a lower bound in the next deleted IDs list.
	PreviousDeletedIdsTime time.Time
}

func (*StartRefreshToken) isTokenSubtype() {}

// RefreshToken represents a refresh phase.
type RefreshToken struct {
	// The upper bound for the timestamp comparisons in
	// this refresh phase. This is equal to the time that
	// the first request in this phase was processed.
	// Constant for the lifetime of the refresh phase.
	PhaseUpperBound time.Time
	// The lower bound for the timestamp comparisons in
	// this refresh phase. This is equal to the initial
	// create time of the token if the previous phase was
	// the initial pagination phase, or the upper bound of
	// the previous refresh phase otherwise.
	// Constant for the lifetime of the refresh phase.
	PhaseLowerBound time.Time
	// The timestamp of the transaction that last listed the deleted IDs,
	// for use as a lower bound in the next deleted IDs list.
	PreviousDeletedIdsTime time.Time
	// The ID of the last item on the previous page.
	LastItemId string
	// The update time of the last item on the previous page.
	LastItemUpdateTime time.Time
}

func (*RefreshToken) isTokenSubtype() {}

// NewPagination creates a new token with the pagination subtype.
func NewPagination(
	ctx context.Context,
	createTime time.Time,
	typ resource.Type,
	grantsHash []byte,
	lastItemId string,
	lastItemCreateTime time.Time,
) (*Token, error) {
	const op = "listtoken.NewPagination"

	switch {
	case createTime.IsZero():
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing create time")
	case typ == resource.Unknown:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing resource type")
	case len(grantsHash) == 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing grants hash")
	case lastItemId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing last item ID")
	case lastItemCreateTime.IsZero():
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing last item create time")
	}

	return &Token{
		CreateTime:   createTime,
		ResourceType: typ,
		GrantsHash:   grantsHash,
		Subtype: &PaginationToken{
			LastItemId:         lastItemId,
			LastItemCreateTime: lastItemCreateTime,
		},
	}, nil
}

// NewStartRefresh creates a new token with a start-refresh subtype.
func NewStartRefresh(
	ctx context.Context,
	createTime time.Time,
	typ resource.Type,
	grantsHash []byte,
	previousDeletedIdsTime time.Time,
	previousPhaseUpperBound time.Time,
) (*Token, error) {
	const op = "listtoken.NewStartRefresh"

	switch {
	case createTime.IsZero():
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing create time")
	case typ == resource.Unknown:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing resource type")
	case len(grantsHash) == 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing grants hash")
	case previousDeletedIdsTime.IsZero():
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing previous deleted ids time")
	case previousPhaseUpperBound.IsZero():
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing previous phase upper bound time")
	}

	return &Token{
		CreateTime:   createTime,
		ResourceType: typ,
		GrantsHash:   grantsHash,
		Subtype: &StartRefreshToken{
			PreviousPhaseUpperBound: previousPhaseUpperBound,
			PreviousDeletedIdsTime:  previousDeletedIdsTime,
		},
	}, nil
}

// NewRefresh creates a new token with a refresh subtype.
func NewRefresh(
	ctx context.Context,
	createTime time.Time,
	typ resource.Type,
	grantsHash []byte,
	previousDeletedIdsTime time.Time,
	phaseUpperBound time.Time,
	phaseLowerBound time.Time,
	lastItemId string,
	lastItemUpdateTime time.Time,
) (*Token, error) {
	const op = "listtoken.NewRefresh"

	switch {
	case createTime.IsZero():
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing create time")
	case typ == resource.Unknown:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing resource type")
	case len(grantsHash) == 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing grants hash")
	case previousDeletedIdsTime.IsZero():
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing previous deleted ids time")
	case phaseUpperBound.IsZero():
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing phase upper bound")
	case phaseLowerBound.IsZero():
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing phase lower bound")
	case lastItemId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing last item ID")
	}

	return &Token{
		CreateTime:   createTime,
		ResourceType: typ,
		GrantsHash:   grantsHash,
		Subtype: &RefreshToken{
			PhaseUpperBound:        phaseUpperBound,
			PhaseLowerBound:        phaseLowerBound,
			PreviousDeletedIdsTime: previousDeletedIdsTime,
			LastItemId:             lastItemId,
			LastItemUpdateTime:     lastItemUpdateTime,
		},
	}, nil
}

// LastItem returns the last item stored in the token.
// This will differ depending on whether the token has
// a pagination, start-refresh or refresh subtype.
func (tk *Token) LastItem(ctx context.Context) (*Item, error) {
	const op = "listtoken.(*Token).LastItem"
	switch st := tk.Subtype.(type) {
	case *PaginationToken:
		return &Item{
			publicId:     st.LastItemId,
			createTime:   timestamp.New(st.LastItemCreateTime),
			resourceType: tk.ResourceType,
		}, nil
	case *RefreshToken:
		return &Item{
			publicId:     st.LastItemId,
			updateTime:   timestamp.New(st.LastItemUpdateTime),
			resourceType: tk.ResourceType,
		}, nil
	case *StartRefreshToken:
		// No item available when starting a new refresh phase.
		return nil, errors.New(ctx, errors.Internal, op, "start refresh tokens have no last item")
	default:
		return nil, errors.New(ctx, errors.Internal, op, fmt.Sprintf("unexpected token subtype: %T", st))
	}
}

// Transition transitions the token to the next state
// in the state machine. See the documentation for the
// [Token] type for an overview of the state machine.
func (tk *Token) Transition(
	ctx context.Context,
	completeListing bool,
	lastItem boundary.Resource,
	deletedIdsTime time.Time,
	listTime time.Time,
) error {
	const op = "listtoken.(*Token).Transition"
	switch st := (tk.Subtype).(type) {
	case *PaginationToken:
		if completeListing {
			// If this is the last page in the pagination, create a
			// start refresh token so subsequent requests are informed
			// that they need to start a new refresh phase.
			tk.Subtype = &StartRefreshToken{
				// In the next refresh phase, both deleted
				// ids and the items listing is relative
				// to the create time of this token.
				PreviousDeletedIdsTime:  tk.CreateTime,
				PreviousPhaseUpperBound: tk.CreateTime,
			}
			return nil
		}
		// Note: this is not a complete listing, which implies that
		// lastItem is populated.
		tk.Subtype = &PaginationToken{
			LastItemId:         lastItem.GetPublicId(),
			LastItemCreateTime: lastItem.GetCreateTime().AsTime(),
		}
	case *StartRefreshToken:
		if completeListing {
			// If this is the only page in the pagination, create a
			// start refresh token so subsequent requests are informed
			// that they need to start a new refresh phase.
			tk.Subtype = &StartRefreshToken{
				PreviousDeletedIdsTime:  deletedIdsTime,
				PreviousPhaseUpperBound: listTime,
			}
			return nil
		}
		tk.Subtype = &RefreshToken{
			PhaseUpperBound:        listTime,
			PhaseLowerBound:        st.PreviousPhaseUpperBound,
			PreviousDeletedIdsTime: deletedIdsTime,
			LastItemId:             lastItem.GetPublicId(),
			LastItemUpdateTime:     lastItem.GetUpdateTime().AsTime(),
		}
	case *RefreshToken:
		if completeListing {
			// If this is the only page in the pagination, create a
			// start refresh token so subsequent requests are informed
			// that they need to start a new refresh phase.
			tk.Subtype = &StartRefreshToken{
				PreviousDeletedIdsTime:  deletedIdsTime,
				PreviousPhaseUpperBound: st.PhaseUpperBound,
			}
			return nil
		}
		// Note: this is not a complete listing, which implies that
		// lastItem is populated.
		tk.Subtype = &RefreshToken{
			PhaseUpperBound:        st.PhaseUpperBound,
			PhaseLowerBound:        st.PhaseLowerBound,
			PreviousDeletedIdsTime: deletedIdsTime,
			LastItemId:             lastItem.GetPublicId(),
			LastItemUpdateTime:     lastItem.GetUpdateTime().AsTime(),
		}
	default:
		return errors.New(ctx, errors.Internal, op, fmt.Sprintf("unexpected token subtype: %T", st))
	}
	return nil
}

// Validate validates the contents of the token.
func (tk *Token) Validate(
	ctx context.Context,
	expectedResourceType resource.Type,
	expectedGrantsHash []byte,
) error {
	const op = "listtoken.Validate"
	switch {
	case tk == nil:
		return errors.New(ctx, errors.InvalidListToken, op, "list token was missing")
	case len(tk.GrantsHash) == 0:
		return errors.New(ctx, errors.InvalidListToken, op, "list token was missing its grants hash")
	case !bytes.Equal(tk.GrantsHash, expectedGrantsHash):
		return errors.New(ctx, errors.InvalidListToken, op, "grants have changed since list token was issued")
	case tk.CreateTime.Before(time.Now().AddDate(0, 0, -30)):
		// Tokens older than 30 days have expired
		return errors.New(ctx, errors.InvalidListToken, op, "list token was expired")
	case tk.ResourceType != expectedResourceType:
		return errors.New(ctx, errors.InvalidListToken, op, "list token resource type does not match expected resource type")
	}
	switch st := tk.Subtype.(type) {
	case *RefreshToken:
		switch {
		case st.PhaseUpperBound.Before(tk.CreateTime):
			// The phase upper bound time should always be equal to or after
			// the create time of the token, as it is the start time of the refresh phase,
			// which is always preceded by a pagination phase.
			return errors.New(ctx, errors.InvalidListToken, op, "list token's refresh component's phase upper bound was before its creation time")
		case st.PhaseLowerBound.Before(tk.CreateTime):
			// The phase lower bound time should always be equal to or after
			// the create time of the token, as for the first refresh phase it is the create time,
			// and for subsequent refresh phases it is the upper bound of the previous refresh phase.
			return errors.New(ctx, errors.InvalidListToken, op, "list token's refresh component's phase lower bound was before its creation time")
		case st.PhaseLowerBound.After(st.PhaseUpperBound):
			// The lower bound should always be before the upper bound.
			return errors.New(ctx, errors.InvalidListToken, op, "list token's refresh component's phase upper bound was before the phase lower bound")
		case st.PreviousDeletedIdsTime.Before(tk.CreateTime):
			// The previous deleted ids time should always be equal to or after
			// the create time of the token.
			return errors.New(ctx, errors.InvalidListToken, op, "list token's refresh component previous deleted ids time was before its creation time")
		case st.LastItemId == "":
			return errors.New(ctx, errors.InvalidListToken, op, "list token's refresh component missing last item ID")
		}
	case *PaginationToken:
		switch {
		case st.LastItemId == "":
			return errors.New(ctx, errors.InvalidListToken, op, "list tokens's pagination component missing last item ID")
		case st.LastItemCreateTime.After(tk.CreateTime):
			// A resource created in the same instant that we did the initial listing
			// would have a timestamp equal to the create time. If it's after the
			// create time, something weird is going on.
			return errors.New(ctx, errors.InvalidListToken, op, "list token's pagination component's last item was created after the token")
		}
	case *StartRefreshToken:
		switch {
		case st.PreviousPhaseUpperBound.Before(tk.CreateTime):
			// The previous phase upper bound time should always be equal to or after
			// the create time of the token, as it is set relative to the upper bound
			// of the previous phase, which for the first refresh phase is the create time,
			// and subsequent refresh phases is the upper bound of the previous refresh phase.
			return errors.New(ctx, errors.InvalidListToken, op, "list token's start refresh component's previous phase upper bound was before its creation time")
		case st.PreviousDeletedIdsTime.Before(tk.CreateTime):
			// The previous deleted ids time should always be equal to or after
			// the create time of the token.
			return errors.New(ctx, errors.InvalidListToken, op, "list token's start refresh component previous deleted ids time was before its creation time")
		}
	}

	return nil
}
