// Copyright (c) Jim Lambert
// SPDX-License-Identifier: MIT

package gldap

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// SIDBytes creates a SID from the provided revision and identifierAuthority
func SIDBytes(revision uint8, identifierAuthority uint16) ([]byte, error) {
	const op = "gldap.SidBytes"
	var identifierAuthorityParts [3]uint16
	identifierAuthorityParts[2] = identifierAuthority

	subAuthorityCount := uint8(0)
	var writer bytes.Buffer
	if err := binary.Write(&writer, binary.LittleEndian, uint8(revision)); err != nil {
		return nil, fmt.Errorf("%s: unable to write revision: %w", op, err)
	}
	if err := binary.Write(&writer, binary.LittleEndian, subAuthorityCount); err != nil {
		return nil, fmt.Errorf("%s: unable to write subauthority count: %w", op, err)
	}
	if err := binary.Write(&writer, binary.BigEndian, identifierAuthorityParts); err != nil {
		return nil, fmt.Errorf("%s: unable to write authority parts: %w", op, err)
	}
	return writer.Bytes(), nil
}

// SIDBytesToString will convert SID bytes to a string
func SIDBytesToString(b []byte) (string, error) {
	const op = "gldap.sidBytesToString"
	reader := bytes.NewReader(b)

	var revision, subAuthorityCount uint8
	var identifierAuthorityParts [3]uint16

	if err := binary.Read(reader, binary.LittleEndian, &revision); err != nil {
		return "", fmt.Errorf("%s: SID %#v convert failed reading Revision: %w", op, b, err)
	}

	if err := binary.Read(reader, binary.LittleEndian, &subAuthorityCount); err != nil {
		return "", fmt.Errorf("%s: SID %#v convert failed reading SubAuthorityCount: %w", op, b, err)
	}

	if err := binary.Read(reader, binary.BigEndian, &identifierAuthorityParts); err != nil {
		return "", fmt.Errorf("%s: SID %#v convert failed reading IdentifierAuthority: %w", op, b, err)
	}
	identifierAuthority := (uint64(identifierAuthorityParts[0]) << 32) + (uint64(identifierAuthorityParts[1]) << 16) + uint64(identifierAuthorityParts[2])

	subAuthority := make([]uint32, subAuthorityCount)
	if err := binary.Read(reader, binary.LittleEndian, &subAuthority); err != nil {
		return "", fmt.Errorf("%s: SID %#v convert failed reading SubAuthority: %w", op, b, err)
	}

	result := fmt.Sprintf("S-%d-%d", revision, identifierAuthority)
	for _, subAuthorityPart := range subAuthority {
		result += fmt.Sprintf("-%d", subAuthorityPart)
	}

	return result, nil
}
