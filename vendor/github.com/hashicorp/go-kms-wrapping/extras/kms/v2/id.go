// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kms

import (
	"fmt"

	"github.com/hashicorp/go-dbw"
)

const (
	// rootKeyPrefix is a prefix used with RootKey IDs
	rootKeyPrefix = "krk"
	// rootKeyVersionPrefix is a prefix used with RootKeyVersion IDs
	rootKeyVersionPrefix = "krkv"
	// dataKeyPrefix is a prefix used with RootKey IDs
	dataKeyPrefix = "kdk"
	// dataKeyVersionPrefix is a prefix used with DataKeyVersion IDs
	dataKeyVersionPrefix = "kdkv"
)

func newRootKeyId() (string, error) {
	const op = "kms.newRootKeyId"
	id, err := dbw.NewId(rootKeyPrefix)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}
	return id, nil
}

func newRootKeyVersionId() (string, error) {
	const op = "kms.newRootKeyVersionId"
	id, err := dbw.NewId(rootKeyVersionPrefix)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}
	return id, nil
}

func newDataKeyId() (string, error) {
	const op = "kms.newDataKeyId"
	id, err := dbw.NewId(dataKeyPrefix)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}
	return id, nil
}

func newDataKeyVersionId() (string, error) {
	const op = "kms.newDataKeyVersionId"
	id, err := dbw.NewId(dataKeyVersionPrefix)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}
	return id, nil
}
