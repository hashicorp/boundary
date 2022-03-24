// Adds an "attributes" field to the OpenAPIv2 message definition of any protobuf message
// that defines a "oneof" field named "attrs".
package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/go-openapi/loads"
	"github.com/go-openapi/spec"
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

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: addattributes <openapiv2 spec path>")
	}

	path := os.Args[1]
	if err := addAttributes(path); err != nil {
		log.Fatal("failed to add attributes: ", err)
	}
}

func addAttributes(path string) error {
	messages := make(map[string]struct{})
	protoregistry.GlobalTypes.RangeMessages(func(mt protoreflect.MessageType) bool {
		md := mt.Descriptor()
		if md.Oneofs().ByName("attrs") != nil {
			messages[string(md.FullName())] = struct{}{}
		}
		return true
	})
	if len(messages) == 0 {
		log.Print(`No messages with "oneof" named "attrs" found`)
		return nil
	}

	log.Printf("Loading spec at %q", path)
	doc, err := loads.JSONSpec(path)
	if err != nil {
		return fmt.Errorf("failed to load spec at path %q: %w", path, err)
	}
	openapiSpec := doc.Spec()
	for name, definition := range openapiSpec.Definitions {
		if _, ok := messages[name]; ok {
			attributesSchema := spec.Schema{}
			attributesSchema.Type = spec.StringOrArray{"object"}
			attributesSchema.Description = "The attributes that are applicable for the specific type."
			definition.Properties["attributes"] = attributesSchema
		}
	}

	json, err := json.MarshalIndent(openapiSpec, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal json: %w", err)
	}

	// Overwrite existing json with the updated json spec
	log.Printf("Overwriting spec at %q", path)
	return ioutil.WriteFile(path, json, os.ModePerm)
}
