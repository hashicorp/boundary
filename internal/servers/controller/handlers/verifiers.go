package handlers

import (
	"regexp"
	"strings"

	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/hashicorp/boundary/internal/gen/controller/api/resources/scopes"
	"google.golang.org/genproto/protobuf/field_mask"
)

type CustomValidatorFunc func() map[string]string

var NoopValidatorFn CustomValidatorFunc = func() map[string]string { return nil }

type ApiResource interface {
	GetId() string
	GetScope() *scopes.ScopeInfo
	GetName() *wrappers.StringValue
	GetDescription() *wrappers.StringValue
	GetCreatedTime() *timestamp.Timestamp
	GetUpdatedTime() *timestamp.Timestamp
	GetVersion() uint32
}

func ValidateCreateRequest(i ApiResource, fn CustomValidatorFunc) error {
	badFields := map[string]string{}
	if i.GetId() != "" {
		badFields["id"] = "This is a read only field."
	}
	if i.GetName() != nil {
		i.GetName().Value = strings.TrimSpace(i.GetName().GetValue())
	}
	if i.GetDescription() != nil {
		i.GetDescription().Value = strings.TrimSpace(i.GetDescription().GetValue())
	}
	if i.GetCreatedTime() != nil {
		badFields["created_time"] = "This is a read only field."
	}
	if i.GetUpdatedTime() != nil {
		badFields["updated_time"] = "This is a read only field."
	}
	if i.GetVersion() != 0 {
		badFields["version"] = "Cannot specify this field in a create request."
	}
	for k, v := range fn() {
		badFields[k] = v
	}
	if len(badFields) > 0 {
		return InvalidArgumentErrorf("Error in provided request.", badFields)
	}
	return nil
}

type UpdateRequest interface {
	GetId() string
	GetUpdateMask() *field_mask.FieldMask
}

func ValidateUpdateRequest(prefix string, r UpdateRequest, i ApiResource, fn CustomValidatorFunc) error {
	badFields := map[string]string{}
	if !ValidId(prefix, r.GetId()) {
		badFields["id"] = "Improperly formatted path identifier."
	}
	if r.GetUpdateMask() == nil {
		badFields["update_mask"] = "UpdateMask not provided but is required to update this resource."
	}

	if i == nil {
		// It is legitimate for no item to be specified in an update request as it indicates all fields provided in
		// the mask will be marked as unset.
		return nil
	}
	if i.GetName() != nil {
		trimmed := strings.TrimSpace(i.GetName().GetValue())
		if trimmed == "" {
			badFields["name"] = "Cannot set empty string as name"
		} else {
			i.GetName().Value = trimmed
		}
	}
	if i.GetDescription() != nil {
		trimmed := strings.TrimSpace(i.GetDescription().GetValue())
		if trimmed == "" {
			badFields["description"] = "Cannot set empty string as description"
		} else {
			i.GetDescription().Value = trimmed
		}
	}
	if i.GetVersion() == 0 {
		badFields["version"] = "Existing resource version is required for an update."
	}
	if i.GetId() != "" {
		badFields["id"] = "This is a read only field and cannot be specified in an update request."
	}
	if i.GetCreatedTime() != nil {
		badFields["created_time"] = "This is a read only field and cannot be specified in an update request."
	}
	if i.GetUpdatedTime() != nil {
		badFields["updated_time"] = "This is a read only field and cannot be specified in an update request."
	}

	for k, v := range fn() {
		badFields[k] = v
	}

	if len(badFields) > 0 {
		return InvalidArgumentErrorf("Error in provided request.", badFields)
	}
	return nil
}

type GetRequest interface {
	GetId() string
}

func ValidateGetRequest(prefix string, r GetRequest, fn CustomValidatorFunc) error {
	badFields := map[string]string{}
	if !ValidId(prefix, r.GetId()) {
		badFields["id"] = "Invalid formatted identifier."
	}
	for k, v := range fn() {
		badFields[k] = v
	}
	if len(badFields) > 0 {
		return InvalidArgumentErrorf("Error in provided request.", badFields)
	}
	return nil
}

type DeleteRequest interface {
	GetId() string
}

func ValidateDeleteRequest(prefix string, r DeleteRequest, fn CustomValidatorFunc) error {
	badFields := map[string]string{}
	if !ValidId(prefix, r.GetId()) {
		badFields["id"] = "Incorrectly formatted identifier."
	}
	for k, v := range fn() {
		badFields[k] = v
	}
	if len(badFields) > 0 {
		return InvalidArgumentErrorf("Error in provided request.", badFields)
	}
	return nil
}

var reInvalidID = regexp.MustCompile("[^A-Za-z0-9]")

func ValidId(prefix, id string) bool {
	prefix = prefix + "_"
	if !strings.HasPrefix(id, prefix) {
		return false
	}
	id = strings.TrimPrefix(id, prefix)
	return !reInvalidID.Match([]byte(id))
}
