// Copyright (c) Jim Lambert
// SPDX-License-Identifier: MIT

package gldap

import (
	"fmt"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// AddMessage is an add request message
type AddMessage struct {
	baseMessage
	// DN identifies the entry being added
	DN string
	// Attributes list the attributes of the new entry
	Attributes []Attribute
	// Controls hold optional controls to send with the request
	Controls []Control
}

// Attribute represents an LDAP attribute within AddMessage
type Attribute struct {
	// Type is the name of the LDAP attribute
	Type string
	// Vals are the LDAP attribute values
	Vals []string
}

func (a *Attribute) encode() *ber.Packet {
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attribute")
	seq.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, a.Type, "Type"))
	set := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "AttributeValue")
	for _, value := range a.Vals {
		set.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, value, "Vals"))
	}
	seq.AppendChild(set)
	return seq
}

func decodeAttribute(berPacket *ber.Packet) (*Attribute, error) {
	const op = "gldap.decodeAttribute"
	const (
		childType     = 0
		childVals     = 1
		childControls = 2
	)
	if berPacket == nil {
		return nil, fmt.Errorf("%s: missing ber packet: %w", op, ErrInvalidParameter)
	}

	var decodedAttribute Attribute

	seq := &packet{
		Packet: berPacket,
	}
	if err := seq.assert(ber.ClassUniversal, ber.TypeConstructed, withTag(ber.TagSequence)); err != nil {
		return nil, fmt.Errorf("%s: missing/invalid attributes ber packet: %w", op, ErrInvalidParameter)
	}
	if err := seq.assert(ber.ClassUniversal, ber.TypePrimitive, withTag(ber.TagOctetString), withAssertChild(childType)); err != nil {
		return nil, fmt.Errorf("%s: missing/invalid attributes type: %w", op, ErrInvalidParameter)
	}
	decodedAttribute.Type = seq.Children[childType].Data.String()

	if err := seq.assert(ber.ClassUniversal, ber.TypeConstructed, withTag(ber.TagSet), withAssertChild(childVals)); err != nil {
		return nil, fmt.Errorf("%s: missing/invalid attributes values: %w", op, ErrInvalidParameter)
	}
	valuesPacket := &packet{
		Packet: seq.Children[childVals],
	}
	decodedAttribute.Vals = make([]string, 0, len(valuesPacket.Children))
	for idx := range valuesPacket.Children {
		if err := valuesPacket.assert(ber.ClassUniversal, ber.TypePrimitive, withTag(ber.TagOctetString), withAssertChild(idx)); err != nil {
			return nil, fmt.Errorf("%s: invalid attribute values packet: %w", op, err)
		}
		decodedAttribute.Vals = append(decodedAttribute.Vals, valuesPacket.Children[idx].Data.String())
	}

	return &decodedAttribute, nil
}
