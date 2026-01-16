// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package subtypes

import (
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/gen/testing/attribute"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestProtoAttributeKey(t *testing.T) {
	cases := []struct {
		name     string
		msg      proto.Message
		subtype  globals.Subtype
		expected protoreflect.FullName
	}{
		{
			"TestResource/sub_resource",
			&attribute.TestResource{},
			"sub_resource",
			"testing.attribute.v1.TestResource.sub_resource_attributes",
		},
		{
			"TestResource/default",
			&attribute.TestResource{},
			defaultSubtype,
			"testing.attribute.v1.TestResource.attributes",
		},
		{
			"TestResource/unknown",
			&attribute.TestResource{},
			globals.UnknownSubtype,
			"testing.attribute.v1.TestResource.attributes",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			k, err := attributeField(tc.msg.ProtoReflect().Descriptor(), tc.subtype)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, k.FullName())
		})
	}
}

func TestProtoAttributeKeyErrors(t *testing.T) {
	cases := []struct {
		name        string
		msg         proto.Message
		subtype     globals.Subtype
		expectedErr string
	}{
		{
			"TestNoAttributes/sub_resource",
			&attribute.TestNoAttributes{},
			"sub_resource",
			"proto message testing.attribute.v1.TestNoAttributes not registered",
		},
		{
			"TestNoAttributes/default",
			&attribute.TestNoAttributes{},
			defaultSubtype,
			"proto message testing.attribute.v1.TestNoAttributes not registered",
		},
		{
			"TestNoAttributes/unknown",
			&attribute.TestNoAttributes{},
			globals.UnknownSubtype,
			"proto message testing.attribute.v1.TestNoAttributes not registered",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := attributeField(tc.msg.ProtoReflect().Descriptor(), tc.subtype)
			require.EqualError(t, err, tc.expectedErr)
		})
	}
}

func TestRegisterErrors(t *testing.T) {
	cases := []struct {
		name        string
		msg         proto.Message
		expectedErr string
	}{
		{
			"AlreadyRegistered",
			&attribute.TestResource{},
			"proto message testing.attribute.v1.TestResource already registered",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := globalAttributeRegistry.register(tc.msg.ProtoReflect().Descriptor())
			require.EqualError(t, err, tc.expectedErr)
		})
	}
}

func TestRegisterNoSubtypes(t *testing.T) {
	ak := attributeRegistry{
		m: make(map[protoreflect.FullName]fieldMap),
	}

	msg := &attribute.TestNoAttributes{}
	d := msg.ProtoReflect().Descriptor()

	err := ak.register(d)
	require.NoError(t, err)

	_, ok := ak.m[d.FullName()]
	require.False(t, ok)
}
