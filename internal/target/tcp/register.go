package tcp

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/target"
)

func init() {
	target.Register(Subtype, newTarget, allocTarget, vet, vetCredentialLibraries, TargetPrefix)
}

const (
	// TargetPrefix is the prefix for public ids of a tcp.Target.
	TargetPrefix = "ttcp"
)

// vet validates that the given target.Target is a tcp.Target and that it
// has a Target store.
func vet(ctx context.Context, t target.Target) error {
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
	return nil
}

// vetCredentialLibraries checks that all of the provided credential libriaries have a CredentialPurpose
// of ApplicationPurpose. Any other CredentialPurpose will result in an error.
func vetCredentialLibraries(ctx context.Context, cls []*target.CredentialLibrary) error {
	const op = "tcp.vetCredentialLibraries"

	for _, cl := range cls {
		if cl.CredentialPurpose != string(credential.ApplicationPurpose) {
			return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("tcp.Target only supports credential purpose: %q", credential.ApplicationPurpose))
		}
	}
	return nil
}
