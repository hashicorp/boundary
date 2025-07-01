// Copyright (c) Jim Lambert
// SPDX-License-Identifier: MIT

package gldap

import ber "github.com/go-asn1-ber/asn1-ber"

// Change operation choices
const (
	AddAttribute       = 0
	DeleteAttribute    = 1
	ReplaceAttribute   = 2
	IncrementAttribute = 3 // (https://tools.ietf.org/html/rfc4525)
)

// ModifyMessage as defined in https://tools.ietf.org/html/rfc4511
type ModifyMessage struct {
	baseMessage
	DN       string
	Changes  []Change
	Controls []Control
}

// Change for a ModifyMessage as defined in https://tools.ietf.org/html/rfc4511
type Change struct {
	// Operation is the type of change to be made
	Operation int64
	// Modification is the attribute to be modified
	Modification PartialAttribute
}

// PartialAttribute for a ModifyMessage as defined in https://tools.ietf.org/html/rfc4511
type PartialAttribute struct {
	// Type is the type of the partial attribute
	Type string
	// Vals are the values of the partial attribute
	Vals []string
}

func (c *Change) encode() *ber.Packet {
	change := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Change")
	change.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(c.Operation), "Operation"))
	change.AppendChild(c.Modification.encode())
	return change
}

func (p *PartialAttribute) encode() *ber.Packet {
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "PartialAttribute")
	seq.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, p.Type, "Type"))
	set := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "AttributeValue")
	for _, value := range p.Vals {
		set.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, value, "Vals"))
	}
	seq.AppendChild(set)
	return seq
}
