package tcp

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/target"
)

func init() {
	target.Register(Subtype, newTarget, allocTarget, vet, vetCredentialSources, TargetPrefix)
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

// vetCredentialSources checks that all the provided credential sources have a CredentialPurpose
// of ApplicationPurpose. Any other CredentialPurpose will result in an error.
func vetCredentialSources(ctx context.Context, libs []*target.CredentialLibrary, creds []*target.CredentialStatic) error {
	const op = "tcp.vetCredentialLibraries"

	for _, c := range libs {
		if c.GetCredentialPurpose() != string(credential.ApplicationPurpose) {
			return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("tcp.Target only supports credential purpose: %q", credential.ApplicationPurpose))
		}
	}
	for _, c := range creds {
		if c.GetCredentialPurpose() != string(credential.ApplicationPurpose) {
			return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("tcp.Target only supports credential purpose: %q", credential.ApplicationPurpose))
		}
	}
	return nil
}
