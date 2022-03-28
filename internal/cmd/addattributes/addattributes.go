package main

import (
	openapi "github.com/go-openapi/spec"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	// Import Protobuf types to register messages
	_ "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/accounts"
	_ "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/authmethods"
	_ "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/authtokens"
	_ "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/credentiallibraries"
	_ "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/credentialstores"
	_ "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/groups"
	_ "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostcatalogs"
	_ "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hosts"
	_ "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostsets"
	_ "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/managedgroups"
	_ "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/plugins"
	_ "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/roles"
	_ "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
	_ "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/sessions"
	_ "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/targets"
	_ "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/users"
)

// AddAttributes adds the "attributes" field to any protobuf message that defines a "oneof" field named "attrs".
// It mutates the input spec directly.
func AddAttributes(spec *openapi.Swagger) error {
	messages := make(map[string]struct{})
	protoregistry.GlobalTypes.RangeMessages(func(mt protoreflect.MessageType) bool {
		md := mt.Descriptor()
		if md.Oneofs().ByName("attrs") != nil {
			messages[string(md.FullName())] = struct{}{}
		}
		return true
	})
	if len(messages) == 0 {
		return nil
	}
	for name, definition := range spec.Definitions {
		if _, ok := messages[name]; ok {
			attributesSchema := openapi.Schema{}
			attributesSchema.Type = openapi.StringOrArray{"object"}
			attributesSchema.Description = "The attributes that are applicable for the specific type."
			definition.Properties["attributes"] = attributesSchema
		}
	}
	return nil
}
