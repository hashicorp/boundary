package tcp

import (
	"context"
	"fmt"
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
		if strings.EqualFold("defaultport", f) && tt.GetDefaultPort() == 0 {
			return errors.New(ctx, errors.InvalidParameter, op, "clearing or setting default port to zero")
		}
	}

	return nil
}

// VetCredentialLibraries checks that all of the provided credential libriaries have a CredentialPurpose
// of ApplicationPurpose. Any other CredentialPurpose will result in an error.
func (h targetHooks) VetCredentialLibraries(ctx context.Context, cls []*target.CredentialLibrary) error {
	const op = "tcp.vetCredentialLibraries"

	for _, cl := range cls {
		if cl.CredentialPurpose != string(credential.ApplicationPurpose) {
			return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("tcp.Target only supports credential purpose: %q", credential.ApplicationPurpose))
		}
	}
	return nil
}
