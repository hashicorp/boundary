// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package event

import "github.com/hashicorp/eventlogger/filters/encrypt"

// Tags implements the encrypt.Taggable interface which allows
// TestEventAuthenRequest Attributes to be classified for the encrypt filter.
func (req *TestAuthenticateRequest) Tags() ([]encrypt.PointerTag, error) {
	var tags []encrypt.PointerTag

	if req.Attributes != nil {
		tags = append(tags, encrypt.PointerTag{
			Pointer:        "/Attributes/Fields/password",
			Classification: encrypt.SecretClassification,
			Filter:         encrypt.RedactOperation,
		})
	}

	return tags, nil
}

// Tags implements the encrypt.Taggable interface which allows
// TestEventAuthenResponse Attributes to be classified for the encrypt filter.
func (req *TestAuthenticateResponse) Tags() ([]encrypt.PointerTag, error) {
	var tags []encrypt.PointerTag

	if req.Attributes != nil {
		tags = append(tags, encrypt.PointerTag{
			Pointer:        "/Attributes/Fields/token",
			Classification: encrypt.SecretClassification,
			Filter:         encrypt.RedactOperation,
		})
	}

	return tags, nil
}
