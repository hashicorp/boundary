package handlers

import (
	"errors"
	"testing"

	pb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/users"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func errorIncludesFields(t *testing.T, err error, wantFields []string) {
	t.Helper()
	var apiErr *apiError
	require.True(t, errors.As(err, &apiErr))
	var gotFields []string
	for _, d := range apiErr.inner.GetDetails().GetRequestFields() {
		gotFields = append(gotFields, d.GetName())
	}
	assert.ElementsMatch(t, gotFields, wantFields)
}

// Throughout this test we will use the User requests, but we could use any request
// message.  User was picked arbitrarily.

func TestValidId(t *testing.T) {
	assert.True(t, ValidId("prefix", "prefix_somerandomid"))
	assert.True(t, ValidId("prefix", "prefix_short"))
	assert.True(t, ValidId("prefix", "prefix_thisisalongidentifierwhichstillworks"))

	assert.False(t, ValidId("prefix", "prefixsomerandomid"))
	assert.False(t, ValidId("prefix", "prefix_this has spaces"))
	assert.False(t, ValidId("prefix", "prefix_includes-dash"))
	assert.False(t, ValidId("prefix", "prefix_other@strange!characters"))
	assert.False(t, ValidId("short", "prefix_short"))
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
			err := ValidateGetRequest(tc.prefix, tc.req, tc.valFn)
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
			err := ValidateDeleteRequest(tc.prefix, tc.req, tc.valFn)
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
			err := ValidateUpdateRequest(tc.prefix, tc.req, tc.item, tc.valFn)
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
