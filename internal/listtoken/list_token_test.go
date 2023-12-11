// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package listtoken_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/boundary"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/listtoken"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_NewPaginationToken(t *testing.T) {
	t.Parallel()
	fiveDaysAgo := time.Now().AddDate(0, 0, -5)
	tests := []struct {
		name               string
		createdTime        time.Time
		typ                resource.Type
		grantsHash         []byte
		lastItemId         string
		lastItemCreateTime time.Time
		want               *listtoken.Token
		wantErrString      string
		wantErrCode        errors.Code
	}{
		{
			name:               "valid list+pagination token",
			createdTime:        fiveDaysAgo,
			typ:                resource.Target,
			grantsHash:         []byte("some hash"),
			lastItemId:         "some id",
			lastItemCreateTime: fiveDaysAgo,
			want: &listtoken.Token{
				CreateTime:   fiveDaysAgo,
				ResourceType: resource.Target,
				GrantsHash:   []byte("some hash"),
				Subtype: &listtoken.PaginationToken{
					LastItemId:         "some id",
					LastItemCreateTime: fiveDaysAgo,
				},
			},
		},
		{
			name:               "missing grants hash",
			createdTime:        fiveDaysAgo,
			typ:                resource.Target,
			grantsHash:         nil,
			lastItemId:         "some id",
			lastItemCreateTime: fiveDaysAgo,
			wantErrString:      "missing grants hash",
			wantErrCode:        errors.InvalidParameter,
		},
		{
			name:               "new created time",
			createdTime:        fiveDaysAgo.AddDate(1, 0, 0),
			typ:                resource.Target,
			grantsHash:         []byte("some hash"),
			lastItemId:         "some id",
			lastItemCreateTime: fiveDaysAgo,
			wantErrString:      "create time is in the future",
			wantErrCode:        errors.InvalidParameter,
		},
		{
			name:               "old created time",
			createdTime:        fiveDaysAgo.AddDate(-1, 0, 0),
			typ:                resource.Target,
			grantsHash:         []byte("some hash"),
			lastItemId:         "some id",
			lastItemCreateTime: fiveDaysAgo,
			wantErrString:      "create time is too old",
			wantErrCode:        errors.InvalidParameter,
		},
		{
			name:               "new updated time",
			createdTime:        fiveDaysAgo,
			typ:                resource.Target,
			grantsHash:         []byte("some hash"),
			lastItemId:         "some id",
			lastItemCreateTime: fiveDaysAgo.AddDate(1, 0, 0),
			wantErrString:      "last item create time is in the future",
			wantErrCode:        errors.InvalidParameter,
		},
		{
			name:               "missing last item id",
			createdTime:        fiveDaysAgo,
			typ:                resource.Target,
			grantsHash:         []byte("some hash"),
			lastItemId:         "",
			lastItemCreateTime: fiveDaysAgo,
			wantErrString:      "missing last item ID",
			wantErrCode:        errors.InvalidParameter,
		},
		{
			name:               "new last item updated time",
			createdTime:        fiveDaysAgo,
			typ:                resource.Target,
			grantsHash:         []byte("some hash"),
			lastItemId:         "some id",
			lastItemCreateTime: fiveDaysAgo.AddDate(1, 0, 0),
			wantErrString:      "last item create time is in the future",
			wantErrCode:        errors.InvalidParameter,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := listtoken.NewPagination(context.Background(), tt.createdTime, tt.typ, tt.grantsHash, tt.lastItemId, tt.lastItemCreateTime)
			if tt.wantErrString != "" {
				require.ErrorContains(t, err, tt.wantErrString)
				require.Equal(t, errors.Convert(err).Code, tt.wantErrCode)
				return
			}
			require.NoError(t, err)
			require.Empty(t, cmp.Diff(got, tt.want))
		})
	}
}

func Test_NewStartRefreshToken(t *testing.T) {
	t.Parallel()
	fiveDaysAgo := time.Now().AddDate(0, 0, -5)
	tests := []struct {
		name                   string
		createdTime            time.Time
		typ                    resource.Type
		grantsHash             []byte
		previousDeletedIdsTime time.Time
		phaseLowerBound        time.Time
		want                   *listtoken.Token
		wantErrString          string
		wantErrCode            errors.Code
	}{
		{
			name:                   "valid list+start-refresh token",
			createdTime:            fiveDaysAgo,
			typ:                    resource.Target,
			grantsHash:             []byte("some hash"),
			previousDeletedIdsTime: fiveDaysAgo,
			phaseLowerBound:        fiveDaysAgo,
			want: &listtoken.Token{
				CreateTime:   fiveDaysAgo,
				ResourceType: resource.Target,
				GrantsHash:   []byte("some hash"),
				Subtype: &listtoken.StartRefreshToken{
					PreviousPhaseUpperBound: fiveDaysAgo,
					PreviousDeletedIdsTime:  fiveDaysAgo,
				},
			},
		},
		{
			name:                   "missing grants hash",
			createdTime:            fiveDaysAgo,
			typ:                    resource.Target,
			grantsHash:             nil,
			previousDeletedIdsTime: fiveDaysAgo,
			phaseLowerBound:        fiveDaysAgo,
			wantErrString:          "missing grants hash",
			wantErrCode:            errors.InvalidParameter,
		},
		{
			name:                   "new created time",
			createdTime:            fiveDaysAgo.AddDate(1, 0, 0),
			typ:                    resource.Target,
			grantsHash:             []byte("some hash"),
			previousDeletedIdsTime: fiveDaysAgo,
			phaseLowerBound:        fiveDaysAgo,
			wantErrString:          "create time is in the future",
			wantErrCode:            errors.InvalidParameter,
		},
		{
			name:                   "old created time",
			createdTime:            fiveDaysAgo.AddDate(-1, 0, 0),
			typ:                    resource.Target,
			grantsHash:             []byte("some hash"),
			previousDeletedIdsTime: fiveDaysAgo,
			phaseLowerBound:        fiveDaysAgo,
			wantErrString:          "create time is too old",
			wantErrCode:            errors.InvalidParameter,
		},
		{
			name:                   "new previous deleted ids time",
			createdTime:            fiveDaysAgo,
			typ:                    resource.Target,
			grantsHash:             []byte("some hash"),
			previousDeletedIdsTime: fiveDaysAgo.AddDate(1, 0, 0),
			phaseLowerBound:        fiveDaysAgo,
			wantErrString:          "previous deleted ids time is in the future",
			wantErrCode:            errors.InvalidParameter,
		},
		{
			name:                   "new previous phase upper bound",
			createdTime:            fiveDaysAgo,
			typ:                    resource.Target,
			grantsHash:             []byte("some hash"),
			previousDeletedIdsTime: fiveDaysAgo,
			phaseLowerBound:        fiveDaysAgo.AddDate(1, 0, 0),
			wantErrString:          "previous phase upper bound is in the future",
			wantErrCode:            errors.InvalidParameter,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := listtoken.NewStartRefresh(context.Background(), tt.createdTime, tt.typ, tt.grantsHash, tt.previousDeletedIdsTime, tt.phaseLowerBound)
			if tt.wantErrString != "" {
				require.ErrorContains(t, err, tt.wantErrString)
				require.Equal(t, errors.Convert(err).Code, tt.wantErrCode)
				return
			}
			require.NoError(t, err)
			require.Empty(t, cmp.Diff(got, tt.want))
		})
	}
}

func Test_NewRefreshToken(t *testing.T) {
	t.Parallel()
	timeNow := time.Now()
	fiveDaysAgo := timeNow.AddDate(0, 0, -5)
	fourDaysAgo := timeNow.AddDate(0, 0, -4)
	tests := []struct {
		name                  string
		createdTime           time.Time
		typ                   resource.Type
		grantsHash            []byte
		phaseUpperBound       time.Time
		phaseLowerBound       time.Time
		previousDeleteIdsTime time.Time
		lastItemId            string
		lastItemUpdateTime    time.Time
		want                  *listtoken.Token
		wantErrString         string
		wantErrCode           errors.Code
	}{
		{
			name:                  "valid list+refresh token",
			createdTime:           fiveDaysAgo,
			typ:                   resource.Target,
			grantsHash:            []byte("some hash"),
			phaseUpperBound:       timeNow,
			phaseLowerBound:       fiveDaysAgo,
			previousDeleteIdsTime: fiveDaysAgo,
			lastItemId:            "some id",
			lastItemUpdateTime:    fourDaysAgo,
			want: &listtoken.Token{
				CreateTime:   fiveDaysAgo,
				ResourceType: resource.Target,
				GrantsHash:   []byte("some hash"),
				Subtype: &listtoken.RefreshToken{
					PhaseUpperBound:        timeNow,
					PhaseLowerBound:        fiveDaysAgo,
					PreviousDeletedIdsTime: fiveDaysAgo,
					LastItemId:             "some id",
					LastItemUpdateTime:     fourDaysAgo,
				},
			},
		},
		{
			name:                  "missing grants hash",
			createdTime:           fiveDaysAgo,
			typ:                   resource.Target,
			grantsHash:            nil,
			phaseUpperBound:       timeNow,
			phaseLowerBound:       fiveDaysAgo,
			previousDeleteIdsTime: fiveDaysAgo,
			lastItemId:            "some id",
			lastItemUpdateTime:    fourDaysAgo,
			wantErrString:         "missing grants hash",
			wantErrCode:           errors.InvalidParameter,
		},
		{
			name:                  "new created time",
			createdTime:           fiveDaysAgo.AddDate(1, 0, 0),
			typ:                   resource.Target,
			grantsHash:            []byte("some hash"),
			phaseUpperBound:       timeNow,
			phaseLowerBound:       fiveDaysAgo,
			previousDeleteIdsTime: fiveDaysAgo,
			lastItemId:            "some id",
			lastItemUpdateTime:    fourDaysAgo,
			wantErrString:         "create time is in the future",
			wantErrCode:           errors.InvalidParameter,
		},
		{
			name:                  "old created time",
			createdTime:           fiveDaysAgo.AddDate(-1, 0, 0),
			typ:                   resource.Target,
			grantsHash:            []byte("some hash"),
			phaseUpperBound:       timeNow,
			phaseLowerBound:       fiveDaysAgo,
			previousDeleteIdsTime: fiveDaysAgo,
			lastItemId:            "some id",
			lastItemUpdateTime:    fourDaysAgo,
			wantErrString:         "create time is too old",
			wantErrCode:           errors.InvalidParameter,
		},
		{
			name:                  "new previous deleted ids time",
			createdTime:           fiveDaysAgo,
			typ:                   resource.Target,
			grantsHash:            []byte("some hash"),
			phaseUpperBound:       timeNow,
			phaseLowerBound:       fiveDaysAgo,
			previousDeleteIdsTime: fiveDaysAgo.AddDate(1, 0, 0),
			lastItemId:            "some id",
			lastItemUpdateTime:    fourDaysAgo,
			wantErrString:         "previous deleted ids time is in the future",
			wantErrCode:           errors.InvalidParameter,
		},
		{
			name:                  "phase upper bound in future",
			createdTime:           fiveDaysAgo,
			typ:                   resource.Target,
			grantsHash:            []byte("some hash"),
			phaseUpperBound:       timeNow.AddDate(1, 0, 0),
			phaseLowerBound:       fiveDaysAgo,
			previousDeleteIdsTime: fiveDaysAgo,
			lastItemId:            "some id",
			lastItemUpdateTime:    fourDaysAgo,
			wantErrString:         "phase upper bound is in the future",
			wantErrCode:           errors.InvalidParameter,
		},
		{
			name:                  "phase lower bound in future",
			createdTime:           fiveDaysAgo,
			typ:                   resource.Target,
			grantsHash:            []byte("some hash"),
			phaseUpperBound:       timeNow,
			phaseLowerBound:       fiveDaysAgo.AddDate(1, 0, 0),
			previousDeleteIdsTime: fiveDaysAgo,
			lastItemId:            "some id",
			lastItemUpdateTime:    fourDaysAgo,
			wantErrString:         "phase lower bound is in the future",
			wantErrCode:           errors.InvalidParameter,
		},
		{
			name:                  "phase lower bound newer than upper bound",
			createdTime:           fiveDaysAgo,
			typ:                   resource.Target,
			grantsHash:            []byte("some hash"),
			phaseUpperBound:       fiveDaysAgo,
			phaseLowerBound:       timeNow,
			previousDeleteIdsTime: fiveDaysAgo,
			lastItemId:            "some id",
			lastItemUpdateTime:    fourDaysAgo,
			wantErrString:         "phase lower bound is after phase upper bound",
			wantErrCode:           errors.InvalidParameter,
		},
		{
			name:                  "missing last item ID",
			createdTime:           fiveDaysAgo,
			typ:                   resource.Target,
			grantsHash:            []byte("some hash"),
			phaseUpperBound:       timeNow,
			phaseLowerBound:       fiveDaysAgo,
			previousDeleteIdsTime: fiveDaysAgo,
			lastItemId:            "",
			lastItemUpdateTime:    fourDaysAgo,
			wantErrString:         "missing last item ID",
			wantErrCode:           errors.InvalidParameter,
		},
		{
			name:                  "last item update time in future",
			createdTime:           fiveDaysAgo,
			typ:                   resource.Target,
			grantsHash:            []byte("some hash"),
			phaseUpperBound:       timeNow,
			phaseLowerBound:       fiveDaysAgo,
			previousDeleteIdsTime: fiveDaysAgo,
			lastItemId:            "some id",
			lastItemUpdateTime:    fourDaysAgo.AddDate(1, 0, 0),
			wantErrString:         "last item update time is in the future",
			wantErrCode:           errors.InvalidParameter,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := listtoken.NewRefresh(
				context.Background(),
				tt.createdTime,
				tt.typ,
				tt.grantsHash,
				tt.previousDeleteIdsTime,
				tt.phaseUpperBound,
				tt.phaseLowerBound,
				tt.lastItemId,
				tt.lastItemUpdateTime,
			)
			if tt.wantErrString != "" {
				require.ErrorContains(t, err, tt.wantErrString)
				require.Equal(t, errors.Convert(err).Code, tt.wantErrCode)
				return
			}
			require.NoError(t, err)
			require.Empty(t, cmp.Diff(got, tt.want))
		})
	}
}

func Test_ValidateListToken(t *testing.T) {
	t.Parallel()
	fiveDaysAgo := time.Now().AddDate(0, 0, -5)
	tests := []struct {
		name          string
		token         *listtoken.Token
		grantsHash    []byte
		resourceType  resource.Type
		wantErrString string
		wantErrCode   errors.Code
	}{
		{
			name: "valid token",
			token: &listtoken.Token{
				CreateTime:   fiveDaysAgo,
				ResourceType: resource.Target,
				GrantsHash:   []byte("some hash"),
			},
			grantsHash:   []byte("some hash"),
			resourceType: resource.Target,
		},
		{
			name:          "nil token",
			token:         nil,
			grantsHash:    []byte("some hash"),
			resourceType:  resource.Target,
			wantErrString: "list token was missing",
			wantErrCode:   errors.InvalidListToken,
		},
		{
			name: "no grants hash",
			token: &listtoken.Token{
				CreateTime:   fiveDaysAgo,
				ResourceType: resource.Target,
				GrantsHash:   nil,
			},
			grantsHash:    []byte("some hash"),
			resourceType:  resource.Target,
			wantErrString: "list token was missing its grants hash",
			wantErrCode:   errors.InvalidListToken,
		},
		{
			name: "changed grants hash",
			token: &listtoken.Token{
				CreateTime:   fiveDaysAgo,
				ResourceType: resource.Target,
				GrantsHash:   []byte("some hash"),
			},
			grantsHash:    []byte("some other hash"),
			resourceType:  resource.Target,
			wantErrString: "grants have changed since list token was issued",
			wantErrCode:   errors.InvalidListToken,
		},
		{
			name: "created in the future",
			token: &listtoken.Token{
				CreateTime:   time.Now().AddDate(1, 0, 0),
				ResourceType: resource.Target,
				GrantsHash:   []byte("some hash"),
			},
			grantsHash:    []byte("some hash"),
			resourceType:  resource.Target,
			wantErrString: "list token was created in the future",
			wantErrCode:   errors.InvalidListToken,
		},
		{
			name: "expired",
			token: &listtoken.Token{
				CreateTime:   time.Now().AddDate(0, 0, -31),
				ResourceType: resource.Target,
				GrantsHash:   []byte("some hash"),
			},
			grantsHash:    []byte("some hash"),
			resourceType:  resource.Target,
			wantErrString: "list token was expired",
			wantErrCode:   errors.InvalidListToken,
		},
		{
			name: "resource type mismatch",
			token: &listtoken.Token{
				CreateTime:   fiveDaysAgo,
				ResourceType: resource.Target,
				GrantsHash:   []byte("some hash"),
			},
			grantsHash:    []byte("some hash"),
			resourceType:  resource.SessionRecording,
			wantErrString: "list token resource type does not match expected resource type",
			wantErrCode:   errors.InvalidListToken,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.token.Validate(context.Background(), tt.resourceType, tt.grantsHash)
			if tt.wantErrString != "" {
				require.ErrorContains(t, err, tt.wantErrString)
				require.Equal(t, errors.Convert(err).Code, tt.wantErrCode)
				return
			}
			require.NoError(t, err)
		})
	}
}

func Test_ValidatePaginationToken(t *testing.T) {
	t.Parallel()
	fiveDaysAgo := time.Now().AddDate(0, 0, -5)
	tests := []struct {
		name          string
		token         *listtoken.Token
		grantsHash    []byte
		resourceType  resource.Type
		wantErrString string
		wantErrCode   errors.Code
	}{
		{
			name: "valid token",
			token: &listtoken.Token{
				CreateTime:   fiveDaysAgo,
				ResourceType: resource.Target,
				GrantsHash:   []byte("some hash"),
				Subtype: &listtoken.PaginationToken{
					LastItemId:         "s_1234567890",
					LastItemCreateTime: fiveDaysAgo,
				},
			},
			grantsHash:   []byte("some hash"),
			resourceType: resource.Target,
		},
		{
			name: "last item ID unset",
			token: &listtoken.Token{
				CreateTime:   fiveDaysAgo,
				ResourceType: resource.Target,
				GrantsHash:   []byte("some hash"),
				Subtype: &listtoken.PaginationToken{
					LastItemId:         "",
					LastItemCreateTime: fiveDaysAgo,
				},
			},
			grantsHash:    []byte("some hash"),
			resourceType:  resource.Target,
			wantErrString: "list tokens's pagination component missing last item ID",
			wantErrCode:   errors.InvalidListToken,
		},
		{
			name: "updated in the future",
			token: &listtoken.Token{
				CreateTime:   fiveDaysAgo,
				ResourceType: resource.Target,
				GrantsHash:   []byte("some hash"),
				Subtype: &listtoken.PaginationToken{
					LastItemId:         "s_1234567890",
					LastItemCreateTime: time.Now().AddDate(1, 0, 0),
				},
			},
			grantsHash:    []byte("some hash"),
			resourceType:  resource.Target,
			wantErrString: "list token's pagination component's last item was created in the future",
			wantErrCode:   errors.InvalidListToken,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.token.Validate(context.Background(), tt.resourceType, tt.grantsHash)
			if tt.wantErrString != "" {
				require.ErrorContains(t, err, tt.wantErrString)
				require.Equal(t, errors.Convert(err).Code, tt.wantErrCode)
				return
			}
			require.NoError(t, err)
		})
	}
}

func Test_ValidateStartRefreshToken(t *testing.T) {
	t.Parallel()
	fiveDaysAgo := time.Now().AddDate(0, 0, -5)
	tests := []struct {
		name          string
		token         *listtoken.Token
		grantsHash    []byte
		resourceType  resource.Type
		wantErrString string
		wantErrCode   errors.Code
	}{
		{
			name: "valid token",
			token: &listtoken.Token{
				CreateTime:   fiveDaysAgo,
				ResourceType: resource.Target,
				GrantsHash:   []byte("some hash"),
				Subtype: &listtoken.StartRefreshToken{
					PreviousDeletedIdsTime:  fiveDaysAgo,
					PreviousPhaseUpperBound: fiveDaysAgo,
				},
			},
			grantsHash:   []byte("some hash"),
			resourceType: resource.Target,
		},
		{
			name: "previous phase upper bound before create time",
			token: &listtoken.Token{
				CreateTime:   fiveDaysAgo,
				ResourceType: resource.Target,
				GrantsHash:   []byte("some hash"),
				Subtype: &listtoken.StartRefreshToken{
					PreviousDeletedIdsTime:  fiveDaysAgo,
					PreviousPhaseUpperBound: fiveDaysAgo.AddDate(-1, 0, 0),
				},
			},
			grantsHash:    []byte("some hash"),
			resourceType:  resource.Target,
			wantErrString: "list token's start refresh component's previous phase upper bound was before its creation time",
			wantErrCode:   errors.InvalidListToken,
		},
		{
			name: "previous phase upper bound in future",
			token: &listtoken.Token{
				CreateTime:   fiveDaysAgo,
				ResourceType: resource.Target,
				GrantsHash:   []byte("some hash"),
				Subtype: &listtoken.StartRefreshToken{
					PreviousDeletedIdsTime:  fiveDaysAgo,
					PreviousPhaseUpperBound: fiveDaysAgo.AddDate(1, 0, 0),
				},
			},
			grantsHash:    []byte("some hash"),
			resourceType:  resource.Target,
			wantErrString: "list token's start refresh component's previous phase upper bound was in the future",
			wantErrCode:   errors.InvalidListToken,
		},
		{
			name: "previous deleted ids time before create time",
			token: &listtoken.Token{
				CreateTime:   fiveDaysAgo,
				ResourceType: resource.Target,
				GrantsHash:   []byte("some hash"),
				Subtype: &listtoken.StartRefreshToken{
					PreviousDeletedIdsTime:  fiveDaysAgo.AddDate(-1, 0, 0),
					PreviousPhaseUpperBound: fiveDaysAgo,
				},
			},
			grantsHash:    []byte("some hash"),
			resourceType:  resource.Target,
			wantErrString: "list token's start refresh component previous deleted ids time was before its creation time",
			wantErrCode:   errors.InvalidListToken,
		},
		{
			name: "previous deleted ids time in future",
			token: &listtoken.Token{
				CreateTime:   fiveDaysAgo,
				ResourceType: resource.Target,
				GrantsHash:   []byte("some hash"),
				Subtype: &listtoken.StartRefreshToken{
					PreviousDeletedIdsTime:  fiveDaysAgo.AddDate(1, 0, 0),
					PreviousPhaseUpperBound: fiveDaysAgo,
				},
			},
			grantsHash:    []byte("some hash"),
			resourceType:  resource.Target,
			wantErrString: "list token's start refresh component previous deleted ids time was in the future",
			wantErrCode:   errors.InvalidListToken,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.token.Validate(context.Background(), tt.resourceType, tt.grantsHash)
			if tt.wantErrString != "" {
				require.ErrorContains(t, err, tt.wantErrString)
				require.Equal(t, errors.Convert(err).Code, tt.wantErrCode)
				return
			}
			require.NoError(t, err)
		})
	}
}

func Test_ValidateRefreshToken(t *testing.T) {
	t.Parallel()
	fiveDaysAgo := time.Now().AddDate(0, 0, -5)
	tests := []struct {
		name          string
		token         *listtoken.Token
		grantsHash    []byte
		resourceType  resource.Type
		wantErrString string
		wantErrCode   errors.Code
	}{
		{
			name: "valid token",
			token: &listtoken.Token{
				CreateTime:   fiveDaysAgo,
				ResourceType: resource.Target,
				GrantsHash:   []byte("some hash"),
				Subtype: &listtoken.RefreshToken{
					PhaseUpperBound:        fiveDaysAgo,
					PreviousDeletedIdsTime: fiveDaysAgo,
					PhaseLowerBound:        fiveDaysAgo,
					LastItemId:             "some id",
					LastItemUpdateTime:     fiveDaysAgo,
				},
			},
			grantsHash:   []byte("some hash"),
			resourceType: resource.Target,
		},
		{
			name: "phase upper bound before create time",
			token: &listtoken.Token{
				CreateTime:   fiveDaysAgo,
				ResourceType: resource.Target,
				GrantsHash:   []byte("some hash"),
				Subtype: &listtoken.RefreshToken{
					PhaseUpperBound:        fiveDaysAgo.AddDate(-1, 0, 0),
					PreviousDeletedIdsTime: fiveDaysAgo,
					PhaseLowerBound:        fiveDaysAgo,
					LastItemId:             "some id",
					LastItemUpdateTime:     fiveDaysAgo,
				},
			},
			grantsHash:    []byte("some hash"),
			resourceType:  resource.Target,
			wantErrString: "list token's refresh component's phase upper bound was before its creation time",
			wantErrCode:   errors.InvalidListToken,
		},
		{
			name: "phase upper bound before phase lower bound",
			token: &listtoken.Token{
				CreateTime:   fiveDaysAgo,
				ResourceType: resource.Target,
				GrantsHash:   []byte("some hash"),
				Subtype: &listtoken.RefreshToken{
					PhaseUpperBound:        fiveDaysAgo.AddDate(0, 0, 1),
					PreviousDeletedIdsTime: fiveDaysAgo,
					PhaseLowerBound:        fiveDaysAgo.AddDate(0, 0, 2),
					LastItemId:             "some id",
					LastItemUpdateTime:     fiveDaysAgo,
				},
			},
			grantsHash:    []byte("some hash"),
			resourceType:  resource.Target,
			wantErrString: "list token's refresh component's phase upper bound was before the phase lower bound",
			wantErrCode:   errors.InvalidListToken,
		},
		{
			name: "phase upper bound in future",
			token: &listtoken.Token{
				CreateTime:   fiveDaysAgo,
				ResourceType: resource.Target,
				GrantsHash:   []byte("some hash"),
				Subtype: &listtoken.RefreshToken{
					PhaseUpperBound:        fiveDaysAgo.AddDate(1, 0, 0),
					PreviousDeletedIdsTime: fiveDaysAgo,
					PhaseLowerBound:        fiveDaysAgo,
					LastItemId:             "some id",
					LastItemUpdateTime:     fiveDaysAgo,
				},
			},
			grantsHash:    []byte("some hash"),
			resourceType:  resource.Target,
			wantErrString: "list token's refresh component's phase upper bound was in the future",
			wantErrCode:   errors.InvalidListToken,
		},
		{
			name: "phase lower bound before create time",
			token: &listtoken.Token{
				CreateTime:   fiveDaysAgo,
				ResourceType: resource.Target,
				GrantsHash:   []byte("some hash"),
				Subtype: &listtoken.RefreshToken{
					PhaseUpperBound:        fiveDaysAgo,
					PreviousDeletedIdsTime: fiveDaysAgo,
					PhaseLowerBound:        fiveDaysAgo.AddDate(-1, 0, 0),
					LastItemId:             "some id",
					LastItemUpdateTime:     fiveDaysAgo,
				},
			},
			grantsHash:    []byte("some hash"),
			resourceType:  resource.Target,
			wantErrString: "list token's refresh component's phase lower bound was before its creation time",
			wantErrCode:   errors.InvalidListToken,
		},
		{
			name: "phase lower bound in future",
			token: &listtoken.Token{
				CreateTime:   fiveDaysAgo,
				ResourceType: resource.Target,
				GrantsHash:   []byte("some hash"),
				Subtype: &listtoken.RefreshToken{
					PhaseUpperBound:        fiveDaysAgo,
					PreviousDeletedIdsTime: fiveDaysAgo,
					PhaseLowerBound:        fiveDaysAgo.AddDate(1, 0, 0),
					LastItemId:             "some id",
					LastItemUpdateTime:     fiveDaysAgo,
				},
			},
			grantsHash:    []byte("some hash"),
			resourceType:  resource.Target,
			wantErrString: "list token's refresh component's phase lower bound was in the future",
			wantErrCode:   errors.InvalidListToken,
		},
		{
			name: "previous deleted ids time before create time",
			token: &listtoken.Token{
				CreateTime:   fiveDaysAgo,
				ResourceType: resource.Target,
				GrantsHash:   []byte("some hash"),
				Subtype: &listtoken.RefreshToken{
					PhaseUpperBound:        fiveDaysAgo,
					PreviousDeletedIdsTime: fiveDaysAgo.AddDate(-1, 0, 0),
					PhaseLowerBound:        fiveDaysAgo,
					LastItemId:             "some id",
					LastItemUpdateTime:     fiveDaysAgo,
				},
			},
			grantsHash:    []byte("some hash"),
			resourceType:  resource.Target,
			wantErrString: "list token's refresh component previous deleted ids time was before its creation time",
			wantErrCode:   errors.InvalidListToken,
		},
		{
			name: "previous deleted ids time in future",
			token: &listtoken.Token{
				CreateTime:   fiveDaysAgo,
				ResourceType: resource.Target,
				GrantsHash:   []byte("some hash"),
				Subtype: &listtoken.RefreshToken{
					PhaseUpperBound:        fiveDaysAgo,
					PreviousDeletedIdsTime: fiveDaysAgo.AddDate(1, 0, 0),
					PhaseLowerBound:        fiveDaysAgo,
					LastItemId:             "some id",
					LastItemUpdateTime:     fiveDaysAgo,
				},
			},
			grantsHash:    []byte("some hash"),
			resourceType:  resource.Target,
			wantErrString: "list token's refresh component previous deleted ids time was in the future",
			wantErrCode:   errors.InvalidListToken,
		},
		{
			name: "emtpy last item id",
			token: &listtoken.Token{
				CreateTime:   fiveDaysAgo,
				ResourceType: resource.Target,
				GrantsHash:   []byte("some hash"),
				Subtype: &listtoken.RefreshToken{
					PhaseUpperBound:        fiveDaysAgo,
					PreviousDeletedIdsTime: fiveDaysAgo,
					PhaseLowerBound:        fiveDaysAgo,
					LastItemId:             "",
					LastItemUpdateTime:     fiveDaysAgo,
				},
			},
			grantsHash:    []byte("some hash"),
			resourceType:  resource.Target,
			wantErrString: "list token's refresh component missing last item ID",
			wantErrCode:   errors.InvalidListToken,
		},
		{
			name: "last item update in future",
			token: &listtoken.Token{
				CreateTime:   fiveDaysAgo,
				ResourceType: resource.Target,
				GrantsHash:   []byte("some hash"),
				Subtype: &listtoken.RefreshToken{
					PhaseUpperBound:        fiveDaysAgo,
					PreviousDeletedIdsTime: fiveDaysAgo,
					PhaseLowerBound:        fiveDaysAgo,
					LastItemId:             "some id",
					LastItemUpdateTime:     fiveDaysAgo.AddDate(1, 0, 0),
				},
			},
			grantsHash:    []byte("some hash"),
			resourceType:  resource.Target,
			wantErrString: "list token's refresh component's last item was updated in the future",
			wantErrCode:   errors.InvalidListToken,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.token.Validate(context.Background(), tt.resourceType, tt.grantsHash)
			if tt.wantErrString != "" {
				require.ErrorContains(t, err, tt.wantErrString)
				require.Equal(t, errors.Convert(err).Code, tt.wantErrCode)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestToken_LastItem(t *testing.T) {
	t.Parallel()
	fiveDaysAgo := time.Now().AddDate(0, 0, -5)

	tests := []struct {
		name               string
		token              *listtoken.Token
		wantItemPublicId   string
		wantItemCreateTime *timestamp.Timestamp
		wantItemUpdateTime *timestamp.Timestamp
		wantResourceType   resource.Type
		wantErrString      string
		wantErrCode        errors.Code
	}{
		{
			name: "refresh token returns item with update time",
			token: &listtoken.Token{
				CreateTime:   fiveDaysAgo,
				ResourceType: resource.Target,
				GrantsHash:   []byte("some hash"),
				Subtype: &listtoken.RefreshToken{
					PhaseUpperBound:        fiveDaysAgo.Add(time.Hour),
					PreviousDeletedIdsTime: fiveDaysAgo,
					PhaseLowerBound:        fiveDaysAgo,
					LastItemId:             "some id",
					LastItemUpdateTime:     fiveDaysAgo,
				},
			},
			wantItemPublicId:   "some id",
			wantItemCreateTime: nil,
			wantItemUpdateTime: timestamp.New(fiveDaysAgo),
			wantResourceType:   resource.Target,
		},
		{
			name: "pagination token returns item with create time",
			token: &listtoken.Token{
				CreateTime:   fiveDaysAgo,
				ResourceType: resource.Target,
				GrantsHash:   []byte("some hash"),
				Subtype: &listtoken.PaginationToken{
					LastItemId:         "some id",
					LastItemCreateTime: fiveDaysAgo,
				},
			},
			wantItemPublicId:   "some id",
			wantItemCreateTime: timestamp.New(fiveDaysAgo),
			wantItemUpdateTime: nil,
			wantResourceType:   resource.Target,
		},
		{
			name: "start refresh token returns no item",
			token: &listtoken.Token{
				CreateTime:   fiveDaysAgo,
				ResourceType: resource.Target,
				GrantsHash:   []byte("some hash"),
				Subtype: &listtoken.StartRefreshToken{
					PreviousPhaseUpperBound: fiveDaysAgo,
					PreviousDeletedIdsTime:  fiveDaysAgo,
				},
			},
			wantErrString: "start refresh tokens have no last item",
			wantErrCode:   errors.Internal,
		},
		{
			name: "nil subtype returns no item",
			token: &listtoken.Token{
				CreateTime:   fiveDaysAgo,
				ResourceType: resource.Target,
				GrantsHash:   []byte("some hash"),
				Subtype:      nil,
			},
			wantErrString: "unexpected token subtype",
			wantErrCode:   errors.Internal,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			item, err := tt.token.LastItem(context.Background())
			if tt.wantErrString != "" {
				require.ErrorContains(t, err, tt.wantErrString)
				require.Equal(t, errors.Convert(err).Code, tt.wantErrCode)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantResourceType, item.GetResourceType())
			assert.Equal(t, tt.wantItemCreateTime, item.GetCreateTime())
			assert.Equal(t, tt.wantItemPublicId, item.GetPublicId())
			assert.Equal(t, tt.wantItemUpdateTime, item.GetUpdateTime())
		})
	}
}

func TestToken_Transition(t *testing.T) {
	t.Parallel()
	fiveDaysAgo := time.Now().AddDate(0, 0, -5)

	t.Run("pagination token without complete listing transitions to pagination token", func(t *testing.T) {
		t.Parallel()
		createTime := fiveDaysAgo.Add(-time.Hour)
		tk, err := listtoken.NewPagination(
			context.Background(),
			fiveDaysAgo,
			resource.Target,
			[]byte("some hash"),
			"some id",
			createTime,
		)
		require.NoError(t, err)
		lastItem := &fakeTarget{
			publicId:   "some other id",
			createTime: timestamp.New(fiveDaysAgo.Add(time.Hour)),
		}
		deletedIdsTime := fiveDaysAgo.Add(2 * time.Hour)
		phaseUpperBound := fiveDaysAgo.Add(3 * time.Hour)
		err = tk.Transition(context.Background(), false, lastItem, deletedIdsTime, phaseUpperBound)
		require.NoError(t, err)
		st, ok := tk.Subtype.(*listtoken.PaginationToken)
		require.True(t, ok, "Subtype was %T, not PaginationToken", tk.Subtype)
		assert.Equal(t, lastItem.createTime.AsTime(), st.LastItemCreateTime)
		assert.Equal(t, lastItem.publicId, st.LastItemId)
	})
	t.Run("pagination token with complete listing transitions to start refresh", func(t *testing.T) {
		t.Parallel()
		createTime := fiveDaysAgo.Add(-time.Hour)
		tk, err := listtoken.NewPagination(
			context.Background(),
			fiveDaysAgo,
			resource.Target,
			[]byte("some hash"),
			"some id",
			createTime,
		)
		require.NoError(t, err)
		lastItem := &fakeTarget{
			publicId:   "some other id",
			createTime: timestamp.New(fiveDaysAgo.Add(time.Hour)),
		}
		deletedIdsTime := fiveDaysAgo.Add(2 * time.Hour)
		phaseUpperBound := fiveDaysAgo.Add(3 * time.Hour)
		err = tk.Transition(context.Background(), true, lastItem, deletedIdsTime, phaseUpperBound)
		require.NoError(t, err)
		st, ok := tk.Subtype.(*listtoken.StartRefreshToken)
		require.True(t, ok, "Subtype was %T, not StartRefreshToken", tk.Subtype)
		assert.Equal(t, fiveDaysAgo, st.PreviousDeletedIdsTime)
		assert.Equal(t, fiveDaysAgo, st.PreviousPhaseUpperBound)
	})
	t.Run("start refresh token without complete listing transitions to refresh token", func(t *testing.T) {
		t.Parallel()
		deletedIdsTime := fiveDaysAgo.Add(2 * time.Hour)
		phaseUpperBound := fiveDaysAgo.Add(3 * time.Hour)
		tk, err := listtoken.NewStartRefresh(
			context.Background(),
			fiveDaysAgo,
			resource.Target,
			[]byte("some hash"),
			deletedIdsTime,
			phaseUpperBound,
		)
		require.NoError(t, err)
		lastItem := &fakeTarget{
			publicId:   "some other id",
			updateTime: timestamp.New(fiveDaysAgo.Add(time.Hour)),
		}
		newDeletedIdsTime := fiveDaysAgo.Add(4 * time.Hour)
		newPhaseUpperBound := fiveDaysAgo.Add(5 * time.Hour)
		err = tk.Transition(context.Background(), false, lastItem, newDeletedIdsTime, newPhaseUpperBound)
		require.NoError(t, err)
		st, ok := tk.Subtype.(*listtoken.RefreshToken)
		require.True(t, ok, "Subtype was %T, not RefreshToken", tk.Subtype)
		assert.Equal(t, lastItem.updateTime.AsTime(), st.LastItemUpdateTime)
		assert.Equal(t, lastItem.publicId, st.LastItemId)
		assert.Equal(t, phaseUpperBound, st.PhaseLowerBound)
		assert.Equal(t, newPhaseUpperBound, st.PhaseUpperBound)
		assert.Equal(t, newDeletedIdsTime, st.PreviousDeletedIdsTime)
	})
	t.Run("start refresh token with complete listing transitions to start refresh", func(t *testing.T) {
		t.Parallel()
		deletedIdsTime := fiveDaysAgo.Add(2 * time.Hour)
		phaseUpperBound := fiveDaysAgo.Add(3 * time.Hour)
		tk, err := listtoken.NewStartRefresh(
			context.Background(),
			fiveDaysAgo,
			resource.Target,
			[]byte("some hash"),
			deletedIdsTime,
			phaseUpperBound,
		)
		require.NoError(t, err)
		lastItem := &fakeTarget{
			publicId:   "some other id",
			createTime: timestamp.New(fiveDaysAgo.Add(time.Hour)),
		}
		newDeletedIdsTime := fiveDaysAgo.Add(4 * time.Hour)
		newPhaseUpperBound := fiveDaysAgo.Add(5 * time.Hour)
		err = tk.Transition(context.Background(), true, lastItem, newDeletedIdsTime, newPhaseUpperBound)
		require.NoError(t, err)
		st, ok := tk.Subtype.(*listtoken.StartRefreshToken)
		require.True(t, ok, "Subtype was %T, not StartRefreshToken", tk.Subtype)
		assert.Equal(t, newDeletedIdsTime, st.PreviousDeletedIdsTime)
		assert.Equal(t, newPhaseUpperBound, st.PreviousPhaseUpperBound)
	})
	t.Run("refresh token without complete listing transitions to refresh token", func(t *testing.T) {
		t.Parallel()
		deletedIdsTime := fiveDaysAgo.Add(2 * time.Hour)
		phaseLowerBound := fiveDaysAgo.Add(3 * time.Hour)
		phaseUpperBound := fiveDaysAgo.Add(4 * time.Hour)
		updateTime := fiveDaysAgo.Add(5 * time.Hour)
		tk, err := listtoken.NewRefresh(
			context.Background(),
			fiveDaysAgo,
			resource.Target,
			[]byte("some hash"),
			deletedIdsTime,
			phaseUpperBound,
			phaseLowerBound,
			"some id",
			updateTime,
		)
		require.NoError(t, err)
		lastItem := &fakeTarget{
			publicId:   "some other id",
			updateTime: timestamp.New(fiveDaysAgo.Add(time.Hour)),
		}
		newDeletedIdsTime := fiveDaysAgo.Add(6 * time.Hour)
		newPhaseUpperBound := fiveDaysAgo.Add(7 * time.Hour)
		err = tk.Transition(context.Background(), false, lastItem, newDeletedIdsTime, newPhaseUpperBound)
		require.NoError(t, err)
		st, ok := tk.Subtype.(*listtoken.RefreshToken)
		require.True(t, ok, "Subtype was %T, not RefreshToken", tk.Subtype)
		assert.Equal(t, lastItem.updateTime.AsTime(), st.LastItemUpdateTime)
		assert.Equal(t, lastItem.publicId, st.LastItemId)
		assert.Equal(t, phaseLowerBound, st.PhaseLowerBound)
		assert.Equal(t, phaseUpperBound, st.PhaseUpperBound)
		assert.Equal(t, newDeletedIdsTime, st.PreviousDeletedIdsTime)
	})
	t.Run("refresh token with complete listing transitions to start refresh", func(t *testing.T) {
		t.Parallel()
		deletedIdsTime := fiveDaysAgo.Add(2 * time.Hour)
		phaseLowerBound := fiveDaysAgo.Add(3 * time.Hour)
		phaseUpperBound := fiveDaysAgo.Add(4 * time.Hour)
		updateTime := fiveDaysAgo.Add(5 * time.Hour)
		tk, err := listtoken.NewRefresh(
			context.Background(),
			fiveDaysAgo,
			resource.Target,
			[]byte("some hash"),
			deletedIdsTime,
			phaseUpperBound,
			phaseLowerBound,
			"some id",
			updateTime,
		)
		require.NoError(t, err)
		lastItem := &fakeTarget{
			publicId:   "some other id",
			createTime: timestamp.New(fiveDaysAgo.Add(time.Hour)),
		}
		newDeletedIdsTime := fiveDaysAgo.Add(6 * time.Hour)
		newPhaseUpperBound := fiveDaysAgo.Add(7 * time.Hour)
		err = tk.Transition(context.Background(), true, lastItem, newDeletedIdsTime, newPhaseUpperBound)
		require.NoError(t, err)
		st, ok := tk.Subtype.(*listtoken.StartRefreshToken)
		require.True(t, ok, "Subtype was %T, not StartRefreshToken", tk.Subtype)
		assert.Equal(t, newDeletedIdsTime, st.PreviousDeletedIdsTime)
		assert.Equal(t, phaseUpperBound, st.PreviousPhaseUpperBound)
	})
	t.Run("token without subtype errors", func(t *testing.T) {
		t.Parallel()
		tk := &listtoken.Token{
			CreateTime:   fiveDaysAgo,
			ResourceType: resource.Target,
			GrantsHash:   []byte("some hash"),
			Subtype:      nil,
		}
		lastItem := &fakeTarget{
			publicId:   "some other id",
			createTime: timestamp.New(fiveDaysAgo.Add(time.Hour)),
		}
		newDeletedIdsTime := fiveDaysAgo.Add(6 * time.Hour)
		newPhaseUpperBound := fiveDaysAgo.Add(7 * time.Hour)
		err := tk.Transition(context.Background(), true, lastItem, newDeletedIdsTime, newPhaseUpperBound)
		require.Error(t, err)
		assert.ErrorContains(t, err, "unexpected token subtype")
	})
}

type fakeTarget struct {
	boundary.Resource
	publicId   string
	updateTime *timestamp.Timestamp
	createTime *timestamp.Timestamp
}

func (m *fakeTarget) GetResourceType() resource.Type {
	return resource.Target
}

func (m *fakeTarget) GetPublicId() string {
	return m.publicId
}

func (m *fakeTarget) GetUpdateTime() *timestamp.Timestamp {
	return m.updateTime
}

func (m *fakeTarget) GetCreateTime() *timestamp.Timestamp {
	return m.createTime
}
