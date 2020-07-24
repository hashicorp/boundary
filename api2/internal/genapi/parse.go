package main

import (
	"fmt"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/iancoleman/strcase"
)

func parsePBs() {
	for _, in := range inputStructs {
		msg := in.inProto.ProtoReflect()
		desc := msg.Descriptor()
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

		// Evaluate above, populate below.
		in.generatedStructure.pkg = packageFromFullName(desc.FullName())
		in.generatedStructure.name = string(desc.Name())
		for i := 0; i < desc.Fields().Len(); i++ {
			fd := desc.Fields().Get(i)
			fi := fieldInfo{
				Name:      strcase.ToCamel(string(fd.Name())),
				ProtoName: string(fd.Name()),
			}
			switch k := fd.Kind(); k {
			case protoreflect.MessageKind:
				pkg, name := messageKind(fd)
				if pkg != "" && pkg != in.generatedStructure.pkg {
					name = fmt.Sprintf("%s.%s", pkg, name)
				}
				fi.FieldType = name
			default:
				fi.FieldType = k.String()
			}
			in.generatedStructure.fields = append(in.generatedStructure.fields, fi)
		}
		fmt.Printf("Parsed: %#v\n", in.generatedStructure)
	}
}

func packageFromFullName(fullName protoreflect.FullName) string {
	pkgName := fullName.Parent().Parent().Name()
	if pkgName.IsValid() {
		return string(pkgName)
	}
	return ""
}

var (
	stringValueName = (&wrapperspb.StringValue{}).ProtoReflect().Descriptor().FullName()
	boolValueName   = (&wrapperspb.BoolValue{}).ProtoReflect().Descriptor().FullName()
	timestampName   = (&timestamppb.Timestamp{}).ProtoReflect().Descriptor().FullName()
)

func messageKind(fd protoreflect.FieldDescriptor) (pkg, name string) {
	switch fd.Message().FullName() {
	case stringValueName:
		return "", "string"
	case boolValueName:
		return "", "bool"
	case timestampName:
		return "time", "Time"
	default:
		return packageFromFullName(fd.Message().FullName()), string(fd.Message().Name())
	}
}
