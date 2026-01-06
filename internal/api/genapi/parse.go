// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"fmt"

	_struct "github.com/golang/protobuf/ptypes/struct"
	"github.com/hashicorp/boundary/sdk/pbs/controller/protooptions"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/iancoleman/strcase"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func printDebug(desc protoreflect.MessageDescriptor) {
	fmt.Printf("Evaluating: %q\n", desc.FullName())
	fmt.Printf("Name: %q\n", strcase.ToCamel(string(desc.Name())))
	fmt.Printf("ProtoName: %q\n", desc.Name())
	fmt.Printf("Double Parent: %q\n", desc.FullName().Parent().Parent().Name())
	fmt.Printf("Field Descriptors:\n")
	for i := 0; i < desc.Fields().Len(); i++ {
		fieldDesc := desc.Fields().Get(i)
		fmt.Printf("  field %d: %#v\n", i, fieldDesc)
		fieldDesc.Options()
	}
	fmt.Println()
}

func parsePBs() {
	for _, in := range inputStructs {
		msg := in.inProto.ProtoReflect()
		desc := msg.Descriptor()

		// printDebug(desc)

		// Evaluate above, populate below.
		in.generatedStructure.pkg = packageFromFullName(desc.FullName())
		in.generatedStructure.name = string(desc.Name())
		for i := 0; i < desc.Fields().Len(); i++ {
			fd := desc.Fields().Get(i)
			opts := fd.Options().(*descriptorpb.FieldOptions)
			if subtype := proto.GetExtension(opts, protooptions.E_Subtype).(string); subtype != "" && subtype != "default" {
				// Skip rendering any fields except the default subtype field.
				continue
			}
			if strutil.StrListContains(in.fieldFilter, string(fd.Name())) {
				continue
			}
			fi := fieldInfo{
				Name:      strcase.ToCamel(string(fd.Name())),
				ProtoName: string(fd.Name()),
			}
			// Adjust for slices
			sliceText := ""
			if fd.Cardinality() == protoreflect.Repeated {
				sliceText = "[]"
			}
			// Add generate option info
			if proto.GetExtension(opts, protooptions.E_GenerateSdkOption).(bool) {
				fi.GenerateSdkOption = true
			}
			switch k := fd.Kind(); k {
			case protoreflect.MessageKind:
				ptr, pkg, name := messageKind(fd)
				if pkg != "" && pkg != in.generatedStructure.pkg {
					name = fmt.Sprintf("%s.%s", pkg, name)
				}
				switch name {
				case "v1.AuthorizedCollectionActionsEntry", "v1.CanonicalTagsEntry", "v1.TagsEntry", "v1.ConfigTagsEntry", "v1.ApiTagsEntry":
					fi.FieldType = "map[string][]string"
				default:
					fi.FieldType = sliceText + ptr + name
				}
			case protoreflect.BytesKind:
				fi.FieldType = "[]byte"
			default:
				fi.FieldType = sliceText + k.String()
			}
			in.generatedStructure.fields = append(in.generatedStructure.fields, fi)
		}
		// fmt.Printf("Parsed: %#v\n", in.generatedStructure)
	}
}

func packageFromFullName(fullName protoreflect.FullName) string {
	// Example full name: controller.api.resources.groups.v1.Group
	// Crawling up the parent twice jumps back past v1.Group placing us at "groups".
	pkgName := fullName.Parent().Parent().Name()
	if pkgName.IsValid() {
		return string(pkgName)
	}
	return ""
}

var (
	stringValueName = (&wrapperspb.StringValue{}).ProtoReflect().Descriptor().FullName()
	boolValueName   = (&wrapperspb.BoolValue{}).ProtoReflect().Descriptor().FullName()
	uInt32ValueName = (&wrapperspb.UInt32Value{}).ProtoReflect().Descriptor().FullName()
	int32ValueName  = (&wrapperspb.Int32Value{}).ProtoReflect().Descriptor().FullName()
	structValueName = (&_struct.Struct{}).ProtoReflect().Descriptor().FullName()
	timestampName   = (&timestamppb.Timestamp{}).ProtoReflect().Descriptor().FullName()
	durationName    = (&durationpb.Duration{}).ProtoReflect().Descriptor().FullName()
	valueName       = (&_struct.Value{}).ProtoReflect().Descriptor().FullName()
)

func messageKind(fd protoreflect.FieldDescriptor) (ptr, pkg, name string) {
	switch fd.Message().FullName() {
	case stringValueName:
		return "", "", "string"
	case boolValueName:
		return "", "", "bool"
	case uInt32ValueName:
		return "", "", "uint32"
	case int32ValueName:
		return "", "", "int32"
	case structValueName:
		return "", "", "map[string]interface{}"
	case valueName:
		return "", "", "interface{}"
	case timestampName:
		return "", "time", "Time"
	case durationName:
		return "", "api", "Duration"
	default:
		return "*", packageFromFullName(fd.Message().FullName()), string(fd.Message().Name())
	}
}
