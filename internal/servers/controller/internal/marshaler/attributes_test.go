package marshaler

import (
	"testing"

	"github.com/hashicorp/boundary/internal/gen/testing/attribute"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestProtoAttributeKey(t *testing.T) {
	cases := []struct {
		name        string
		msg         proto.Message
		subtype     string
		expectedKey string
	}{
		{
			"TestResource/sub_resource",
			&attribute.TestResource{},
			"sub_resource",
			"sub_resource_attributes",
		},
		{
			"TestResource/default",
			&attribute.TestResource{},
			"default",
			"attributes",
		},
		{
			"TestResource/unknown",
			&attribute.TestResource{},
			"unknown",
			"attributes",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			k, err := protoAttributeKey(tc.msg, tc.subtype)
			require.NoError(t, err)
			assert.Equal(t, tc.expectedKey, k)
		})
	}
}

func TestProtoAttributeKeyErrors(t *testing.T) {
	cases := []struct {
		name        string
		msg         proto.Message
		subtype     string
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
			"default",
			"proto message testing.attribute.v1.TestNoAttributes not registered",
		},
		{
			"TestNoAttributes/unknown",
			&attribute.TestNoAttributes{},
			"unknown",
			"proto message testing.attribute.v1.TestNoAttributes not registered",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := protoAttributeKey(tc.msg, tc.subtype)
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
			err := globalAttributeKeys.register(tc.msg.ProtoReflect().Descriptor())
			require.EqualError(t, err, tc.expectedErr)
		})
	}
}

func TestRegisterNoSubtypes(t *testing.T) {
	ak := attributeKeys{
		m: make(map[string]keyMap),
	}

	msg := &attribute.TestNoAttributes{}
	d := msg.ProtoReflect().Descriptor()

	err := ak.register(d)
	require.NoError(t, err)

	_, ok := ak.m[string(d.FullName())]
	require.False(t, ok)
}
