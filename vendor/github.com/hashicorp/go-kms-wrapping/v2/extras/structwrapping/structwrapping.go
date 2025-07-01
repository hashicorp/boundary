// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package structwrapping

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"google.golang.org/protobuf/proto"
)

type entry struct {
	index int
}

type encDecMap map[string][2]*entry

func buildEncDecMap(ctx context.Context, in interface{}) (encDecMap, error) {
	val := reflect.ValueOf(in)
	switch {
	case !val.IsValid():
		return nil, errors.New("input not valid")
	case val.IsZero():
		return nil, errors.New("input was not initialized")
	case val.Kind() != reflect.Ptr:
		return nil, errors.New("input not a pointer")
	}

	val = reflect.Indirect(val)
	if val.Kind() != reflect.Struct {
		return nil, errors.New("input not a struct")
	}

	typ := val.Type()
	// plaintext,ciphertext
	edMap := make(encDecMap, typ.NumField()/2)
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		tag, ok := field.Tag.Lookup("wrapping")
		if !ok {
			continue
		}
		tagParts := strings.Split(tag, ",")
		if len(tagParts) != 2 {
			return nil, errors.New("error in wrapping tag specification")
		}

		fieldKind := field.Type.Kind()
		switch tagParts[0] {
		case "pt":
			if !field.Type.ConvertibleTo(reflect.TypeOf([]byte(nil))) {
				return nil, errors.New("plaintext value can not be used as a byte slice")
			}
			curr := edMap[tagParts[1]]
			if curr[0] != nil {
				return nil, errors.New("detected two pt wrapping tags with the same identifier")
			}
			curr[0] = &entry{index: i}
			edMap[tagParts[1]] = curr

		case "ct":
			switch fieldKind {
			case reflect.Ptr:
				if !field.Type.ConvertibleTo(reflect.TypeOf((*wrapping.BlobInfo)(nil))) {
					return nil, errors.New("ciphertext pointer value is not the expected type")
				}
			case reflect.String, reflect.Slice:
				if !field.Type.ConvertibleTo(reflect.TypeOf([]byte(nil))) {
					return nil, errors.New("ciphertext string/byte value cannot be used as a byte slice")
				}
			default:
				return nil, errors.New("unsupported ciphertext value type")
			}
			curr := edMap[tagParts[1]]
			if curr[1] != nil {
				return nil, errors.New("detected two ct wrapping tags with the same identifier")
			}
			curr[1] = &entry{index: i}
			edMap[tagParts[1]] = curr

		default:
			return nil, errors.New("unknown tag type for wrapping tag")
		}
	}

	for k, v := range edMap {
		if v[0] == nil {
			return nil, fmt.Errorf("no pt wrapping tag found for identifier %q", k)
		}
		if v[1] == nil {
			return nil, fmt.Errorf("no ct wrapping tag found for identifier %q", k)
		}
	}

	return edMap, nil
}

// WrapStruct wraps values in the struct. Options are passed through to the
// wrapper Encrypt function.
func WrapStruct(ctx context.Context, wrapper wrapping.Wrapper, in interface{}, opt ...wrapping.Option) error {
	if wrapper == nil {
		return errors.New("nil wrapper passed in")
	}

	edMap, err := buildEncDecMap(ctx, in)
	if err != nil {
		return err
	}

	val := reflect.Indirect(reflect.ValueOf(in))
	for _, v := range edMap {
		encRaw := val.Field(v[0].index).Interface()
		var enc []byte
		switch t := encRaw.(type) {
		case []byte:
			enc = t
		case string:
			enc = []byte(t)
		default:
			return errors.New("could not convert value for encryption to []byte")
		}
		if enc == nil {
			return errors.New("plaintext byte slice is nil")
		}
		blobInfo, err := wrapper.Encrypt(ctx, enc, opt...)
		if err != nil {
			return fmt.Errorf("error wrapping value: %w", err)
		}

		field := val.Field(v[1].index)
		switch field.Interface().(type) {
		case *wrapping.BlobInfo:
			field.Set(reflect.ValueOf(blobInfo))
		case []byte:
			protoBytes, err := proto.Marshal(blobInfo)
			if err != nil {
				return fmt.Errorf("error marshaling proto in byte field: %w", err)
			}
			field.Set(reflect.ValueOf(protoBytes))
		case string:
			protoBytes, err := proto.Marshal(blobInfo)
			if err != nil {
				return fmt.Errorf("error marshaling proto in string field: %w", err)
			}
			field.Set(reflect.ValueOf(string(protoBytes)))
		default:
			return errors.New("could not set value on ciphertext field, incorrect type")
		}
	}

	return nil
}

// UnwrapStruct unwraps values in the struct. Options are passed through to the
// wrapper Dencrypt function.
func UnwrapStruct(ctx context.Context, wrapper wrapping.Wrapper, in interface{}, opt ...wrapping.Option) error {
	if wrapper == nil {
		return errors.New("nil wrapper passed in")
	}

	edMap, err := buildEncDecMap(ctx, in)
	if err != nil {
		return err
	}

	val := reflect.Indirect(reflect.ValueOf(in))
	for _, v := range edMap {
		decRaw := val.Field(v[1].index).Interface()
		var dec *wrapping.BlobInfo
		var decBytes []byte
		switch typedDec := decRaw.(type) {
		case *wrapping.BlobInfo:
			dec = typedDec
		case string:
			decBytes = []byte(typedDec)
		case []byte:
			decBytes = typedDec
		default:
			return errors.New("could not convert value for decryption to a known type")
		}
		if dec == nil {
			if decBytes != nil {
				dec = new(wrapping.BlobInfo)
				if err := proto.Unmarshal(decBytes, dec); err != nil {
					return fmt.Errorf("error unmarshaling encrypted blob info: %w", err)
				}
			} else {
				return errors.New("ciphertext pointer is nil")
			}
		}
		bs, err := wrapper.Decrypt(ctx, dec, opt...)
		if err != nil {
			return fmt.Errorf("error unwrapping value: %w", err)
		}
		field := val.Field(v[0].index)
		switch field.Interface().(type) {
		case []byte:
			field.Set(reflect.ValueOf(bs))
		case string:
			field.Set(reflect.ValueOf(string(bs)))
		default:
			return errors.New("could not set value on plaintext field, incorrect type")
		}
	}

	return nil
}
