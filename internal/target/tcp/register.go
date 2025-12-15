// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package tcp

import (
	"context"
	"fmt"
	"math"
	"strings"

	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/target"
)

type targetHooks struct{}

func init() {
	target.Register(Subtype, targetHooks{}, TargetPrefix)
}

const (
	// TargetPrefix is the prefix for public ids of a tcp.Target.
	TargetPrefix = "ttcp"
)

// Vet validates that the given target.Target is a tcp.Target and that it
// has a Target store.
func (h targetHooks) Vet(ctx context.Context, t target.Target) error {
	const op = "tcp.vet"

	tt, ok := t.(*Target)
	if !ok {
		return errors.New(ctx, errors.InvalidParameter, op, "target is not a tcp.Target")
	}

	if tt == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing target")
	}

	if tt.Target == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing target store")
	}
	if tt.GetDefaultPort() == 0 {
		return errors.New(ctx, errors.InvalidParameter, op, "missing target default port")
	}
	if tt.GetDefaultPort() > math.MaxUint16 {
		return errors.New(ctx, errors.InvalidParameter, op, "invalid default port number")
	}
	if tt.GetDefaultClientPort() > math.MaxUint16 {
		return errors.New(ctx, errors.InvalidParameter, op, "invalid default client port number")
	}
	return nil
}

// VetForUpdate validates that the given target.Target is a tcp.Target,
// and that it has a Target store and that it isn't attempting to clear or
// set to zero the default port.
func (h targetHooks) VetForUpdate(ctx context.Context, t target.Target, paths []string) error {
	const op = "tcp.vetForUpdate"

	tt, ok := t.(*Target)
	if !ok {
		return errors.New(ctx, errors.InvalidParameter, op, "target is not a tcp.Target")
	}

	switch {
	case tt == nil:
		return errors.New(ctx, errors.InvalidParameter, op, "missing target")
	case tt.Target == nil:
		return errors.New(ctx, errors.InvalidParameter, op, "missing target store")
	}

	for _, f := range paths {
		if strings.EqualFold("defaultport", f) {
			if tt.GetDefaultPort() == 0 {
				return errors.New(ctx, errors.InvalidParameter, op, "clearing or setting default port to zero")
			}
			if tt.GetDefaultPort() > math.MaxUint16 {
				return errors.New(ctx, errors.InvalidParameter, op, "invalid default port number")
			}
		}
		if strings.EqualFold("defaultclientport", f) {
			if tt.GetDefaultClientPort() > math.MaxUint16 {
				return errors.New(ctx, errors.InvalidParameter, op, "invalid default client port number")
			}
		}
	}

	return nil
}

// VetCredentialSources checks that all the provided credential sources have a CredentialPurpose
// of BrokeredPurpose. Any other CredentialPurpose will result in an error.
func (h targetHooks) VetCredentialSources(ctx context.Context, libs []*target.CredentialLibrary, creds []*target.StaticCredential) error {
	const op = "tcp.VetCredentialSources"

	for _, c := range libs {
		if c.GetCredentialPurpose() != string(credential.BrokeredPurpose) {
			return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("tcp.Target only supports credential purpose: %q", credential.BrokeredPurpose))
		}
	}
	for _, c := range creds {
		if c.GetCredentialPurpose() != string(credential.BrokeredPurpose) {
			return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("tcp.Target only supports credential purpose: %q", credential.BrokeredPurpose))
		}
	}
	return nil
}
