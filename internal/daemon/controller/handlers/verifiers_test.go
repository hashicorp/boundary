// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package handlers

import (
	"errors"
	"testing"

	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/users"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func errorIncludesFields(t *testing.T, err error, wantFields []string) {
	t.Helper()
	var apiErr *ApiError
	require.True(t, errors.As(err, &apiErr))
	var gotFields []string
	for _, d := range apiErr.Inner.GetDetails().GetRequestFields() {
		gotFields = append(gotFields, d.GetName())
	}
	assert.ElementsMatch(t, gotFields, wantFields)
}

// Throughout this test we will use the User requests, but we could use any request
// message.  User was picked arbitrarily.

func TestValidId(t *testing.T) {
	assert.True(t, ValidId(Id("prefix_somerandomid"), "prefix"))
	assert.True(t, ValidId(Id("prefix_somerandomid"), "notprefix", "prefix"))
	assert.True(t, ValidId(Id("prefix_short"), "prefix"))
	assert.True(t, ValidId(Id("prefix_thisisalongidentifierwhichstillworks"), "prefix"))

	assert.False(t, ValidId(Id("prefixsomerandomid"), "prefix"))
	assert.False(t, ValidId(Id("prefixsomerandomid"), "prefix", "alsobadprefix"))
	assert.False(t, ValidId(Id("prefix_this has spaces"), "prefix"))
	assert.False(t, ValidId(Id("prefix_includes-dash"), "prefix"))
	assert.False(t, ValidId(Id("prefix_other@strange!characters"), "prefix"))
	assert.False(t, ValidId(Id("prefix_short"), "short"))
}

func TestValidDescription(t *testing.T) {
	assert.True(t, ValidDescription("foobar"))
	assert.True(t, ValidDescription("this is\n a long description"))
	assert.False(t, ValidDescription("foo\u200Bbar"))
}

func TestValidName(t *testing.T) {
	assert.True(t, ValidName("foobar"))
	assert.False(t, ValidName("this is\n a long description"))
	assert.False(t, ValidName("foo\u200Bbar"))
}

func TestValidateGetRequest(t *testing.T) {
	cases := []struct {
		name      string
		prefix    string
		req       GetRequest
		valFn     CustomValidatorFunc
		badFields []string
	}{
		{
			name:   "noopvalidator no error",
			prefix: "prefix",
			req: &pbs.GetUserRequest{
				Id: "prefix_someidentifier",
			},
			valFn: NoopValidatorFn,
		},
		{
			name:   "noopvalidator bad prefix",
			prefix: "bad",
			req: &pbs.GetUserRequest{
				Id: "prefix_someidentifier",
			},
			valFn:     NoopValidatorFn,
			badFields: []string{"id"},
		},
		{
			name:   "custom field error",
			prefix: "prefix",
			req: &pbs.GetUserRequest{
				Id: "prefix_someidentifier",
			},
			valFn: func() map[string]string {
				return map[string]string{"test": "test"}
			},
			badFields: []string{"test"},
		},
		{
			name:   "both custom error and prefix",
			prefix: "bad",
			req: &pbs.GetUserRequest{
				Id: "prefix_someidentifier",
			},
			valFn: func() map[string]string {
				return map[string]string{"test": "test"}
			},
			badFields: []string{"id", "test"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateGetRequest(tc.valFn, tc.req, tc.prefix)
			if len(tc.badFields) == 0 {
				if !assert.NoError(t, err) {
					errorIncludesFields(t, err, []string{})
				}
				return
			}
			errorIncludesFields(t, err, tc.badFields)
		})
	}
}

func TestValidateDeleteRequest(t *testing.T) {
	cases := []struct {
		name      string
		prefix    string
		req       DeleteRequest
		valFn     CustomValidatorFunc
		badFields []string
	}{
		{
			name:   "noopvalidator no error",
			prefix: "prefix",
			req: &pbs.DeleteUserRequest{
				Id: "prefix_someidentifier",
			},
			valFn: NoopValidatorFn,
		},
		{
			name:   "noopvalidator bad prefix",
			prefix: "bad",
			req: &pbs.DeleteUserRequest{
				Id: "prefix_someidentifier",
			},
			valFn:     NoopValidatorFn,
			badFields: []string{"id"},
		},
		{
			name:   "custom field error",
			prefix: "prefix",
			req: &pbs.DeleteUserRequest{
				Id: "prefix_someidentifier",
			},
			valFn: func() map[string]string {
				return map[string]string{"test": "test"}
			},
			badFields: []string{"test"},
		},
		{
			name:   "both custom error and prefix",
			prefix: "bad",
			req: &pbs.DeleteUserRequest{
				Id: "prefix_someidentifier",
			},
			valFn: func() map[string]string {
				return map[string]string{"test": "test"}
			},
			badFields: []string{"id", "test"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateDeleteRequest(tc.valFn, tc.req, tc.prefix)
			if len(tc.badFields) == 0 {
				if !assert.NoError(t, err) {
					errorIncludesFields(t, err, []string{})
				}
				return
			}
			errorIncludesFields(t, err, tc.badFields)
		})
	}
}

func TestValidateCreateRequest(t *testing.T) {
	cases := []struct {
		name      string
		item      ApiResource
		valFn     CustomValidatorFunc
		badFields []string
	}{
		{
			name:  "valid",
			item:  &pb.User{},
			valFn: NoopValidatorFn,
		},
		{
			name: "disallow set id",
			item: &pb.User{
				Id: "anything",
			},
			valFn:     NoopValidatorFn,
			badFields: []string{"id"},
		},
		{
			name: "disallow set created",
			item: &pb.User{
				CreatedTime: timestamppb.Now(),
			},
			valFn:     NoopValidatorFn,
			badFields: []string{"created_time"},
		},
		{
			name: "disallow set updated",
			item: &pb.User{
				UpdatedTime: timestamppb.Now(),
			},
			valFn:     NoopValidatorFn,
			badFields: []string{"updated_time"},
		},
		{
			name: "disallow set version",
			item: &pb.User{
				Version: 4,
			},
			valFn:     NoopValidatorFn,
			badFields: []string{"version"},
		},
		{
			name: "custom validator error",
			item: &pb.User{},
			valFn: func() map[string]string {
				return map[string]string{"test": "test"}
			},
			badFields: []string{"test"},
		},
		{
			name: "disallow several fields",
			item: &pb.User{
				Id:          "anything",
				CreatedTime: timestamppb.Now(),
				Version:     4,
			},
			valFn: func() map[string]string {
				return map[string]string{"test": "test"}
			},
			badFields: []string{"id", "created_time", "version", "test"},
		},
		{
			name: "good name",
			item: &pb.User{
				Name: wrapperspb.String("foobar"),
			},
			valFn: NoopValidatorFn,
		},
		{
			name: "bad name",
			item: &pb.User{
				Name: wrapperspb.String("foo\u200Bbar"),
			},
			valFn:     NoopValidatorFn,
			badFields: []string{"name"},
		},
		{
			name: "good description",
			item: &pb.User{
				Description: wrapperspb.String("foobar"),
			},
			valFn: NoopValidatorFn,
		},
		{
			name: "bad description",
			item: &pb.User{
				Description: wrapperspb.String("foo\u200Bbar"),
			},
			valFn:     NoopValidatorFn,
			badFields: []string{"description"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateCreateRequest(tc.item, tc.valFn)
			if len(tc.badFields) == 0 {
				if !assert.NoError(t, err) {
					errorIncludesFields(t, err, []string{})
				}
				return
			}
			errorIncludesFields(t, err, tc.badFields)
		})
	}
}

func TestValidateUpdateRequest(t *testing.T) {
	cases := []struct {
		name      string
		prefix    string
		req       UpdateRequest
		item      ApiResource
		valFn     CustomValidatorFunc
		badFields []string
	}{
		{
			name:   "valid",
			prefix: "prefix",
			req: &pbs.UpdateUserRequest{
				Id:         "prefix_something",
				UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"anything"}},
			},
			item: &pb.User{
				Version: 1,
			},
			valFn: NoopValidatorFn,
		},
		{
			name:   "missing mask",
			prefix: "prefix",
			req: &pbs.UpdateUserRequest{
				Id: "prefix_something",
			},
			item: &pb.User{
				Version: 1,
			},
			valFn:     NoopValidatorFn,
			badFields: []string{"update_mask"},
		},
		{
			name:   "bad id",
			prefix: "prefix",
			req: &pbs.UpdateUserRequest{
				Id:         "mismatched_prefix",
				UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"anything"}},
			},
			item: &pb.User{
				Version: 1,
			},
			valFn:     NoopValidatorFn,
			badFields: []string{"id"},
		},
		{
			name:   "good name",
			prefix: "prefix",
			req: &pbs.UpdateUserRequest{
				Id:         "prefix_something",
				UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"anything"}},
			},
			item: &pb.User{
				Version: 1,
				Name:    wrapperspb.String("foobar"),
			},
			valFn: NoopValidatorFn,
		},
		{
			name:   "bad name",
			prefix: "prefix",
			req: &pbs.UpdateUserRequest{
				Id:         "prefix_something",
				UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"anything"}},
			},
			item: &pb.User{
				Version: 1,
				Name:    wrapperspb.String("foo\u200Bbar"),
			},
			valFn:     NoopValidatorFn,
			badFields: []string{"name"},
		},
		{
			name:   "good description",
			prefix: "prefix",
			req: &pbs.UpdateUserRequest{
				Id:         "prefix_something",
				UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"anything"}},
			},
			item: &pb.User{
				Version:     1,
				Description: wrapperspb.String("foobar"),
			},
			valFn: NoopValidatorFn,
		},
		{
			name:   "bad description",
			prefix: "prefix",
			req: &pbs.UpdateUserRequest{
				Id:         "prefix_something",
				UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"anything"}},
			},
			item: &pb.User{
				Version:     1,
				Description: wrapperspb.String("foo\u200Bbar"),
			},
			valFn:     NoopValidatorFn,
			badFields: []string{"description"},
		},
		{
			name:   "missing version",
			prefix: "prefix",
			req: &pbs.UpdateUserRequest{
				Id:         "prefix_something",
				UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"anything"}},
			},
			item:      &pb.User{},
			valFn:     NoopValidatorFn,
			badFields: []string{"version"},
		},
		{
			name:   "bad create time",
			prefix: "prefix",
			req: &pbs.UpdateUserRequest{
				Id:         "prefix_something",
				UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"anything"}},
			},
			item: &pb.User{
				Version:     1,
				CreatedTime: timestamppb.Now(),
			},
			valFn:     NoopValidatorFn,
			badFields: []string{"created_time"},
		},
		{
			name:   "bad updated time",
			prefix: "prefix",
			req: &pbs.UpdateUserRequest{
				Id:         "prefix_something",
				UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"anything"}},
			},
			item: &pb.User{
				Version:     1,
				UpdatedTime: timestamppb.Now(),
			},
			valFn:     NoopValidatorFn,
			badFields: []string{"updated_time"},
		},
		{
			name:   "bad defined id on item",
			prefix: "prefix",
			req: &pbs.UpdateUserRequest{
				Id:         "prefix_something",
				UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"anything"}},
			},
			item: &pb.User{
				Id:      "prefix_something",
				Version: 1,
			},
			valFn:     NoopValidatorFn,
			badFields: []string{"id"},
		},
		{
			name:   "custom validator error",
			prefix: "prefix",
			req: &pbs.UpdateUserRequest{
				Id:         "prefix_something",
				UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"anything"}},
			},
			item: &pb.User{
				Version: 1,
			},
			valFn: func() map[string]string {
				return map[string]string{
					"test": "test",
				}
			},
			badFields: []string{"test"},
		},
		{
			name:      "multiple",
			prefix:    "prefix",
			req:       &pbs.UpdateUserRequest{},
			item:      &pb.User{},
			valFn:     NoopValidatorFn,
			badFields: []string{"id", "update_mask", "version"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateUpdateRequest(tc.req, tc.item, tc.valFn, tc.prefix)
			if len(tc.badFields) == 0 {
				if !assert.NoError(t, err) {
					errorIncludesFields(t, err, []string{})
				}
				return
			}
			errorIncludesFields(t, err, tc.badFields)
		})
	}
}
