package main

import (
	"fmt"

	_struct "github.com/golang/protobuf/ptypes/struct"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/hashicorp/boundary/internal/gen/controller/protooptions"

	"github.com/iancoleman/strcase"
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

		//printDebug(desc)

		// Evaluate above, populate below.
		in.generatedStructure.pkg = packageFromFullName(desc.FullName())
		in.generatedStructure.name = string(desc.Name())
		for i := 0; i < desc.Fields().Len(); i++ {
			fd := desc.Fields().Get(i)
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
			opts := fd.Options().(*descriptorpb.FieldOptions)
			if proto.GetExtension(opts, protooptions.E_GenerateSdkOption).(bool) {
				fi.GenerateSdkOption = true
			}
			switch k := fd.Kind(); k {
			case protoreflect.MessageKind:
				ptr, pkg, name := messageKind(fd)
				if pkg != "" && pkg != in.generatedStructure.pkg {
					name = fmt.Sprintf("%s.%s", pkg, name)
				}
				fi.FieldType = sliceText + ptr + name
			default:
				fi.FieldType = sliceText + k.String()
			}
			in.generatedStructure.fields = append(in.generatedStructure.fields, fi)
		}
		//fmt.Printf("Parsed: %#v\n", in.generatedStructure)
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
	structValueName = (&_struct.Struct{}).ProtoReflect().Descriptor().FullName()
	timestampName   = (&timestamppb.Timestamp{}).ProtoReflect().Descriptor().FullName()
)

func messageKind(fd protoreflect.FieldDescriptor) (ptr, pkg, name string) {
	switch fd.Message().FullName() {
	case stringValueName:
		return "", "", "string"
	case boolValueName:
		return "", "", "bool"
	case uInt32ValueName:
		return "", "", "uint32"
	case structValueName:
		return "", "", "map[string]interface{}"
	case timestampName:
		return "", "time", "Time"
	default:
		return "*", packageFromFullName(fd.Message().FullName()), string(fd.Message().Name())
	}
}
