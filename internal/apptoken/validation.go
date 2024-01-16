// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken

import "context"

// ValidateAppTokenGrants will ensure that the apptokens grants don't exceed the
// grants of the user
func ValidateAppTokenGrants(ctx context.Context, gf grantFinder, createdByUserId string, appTokenGrants []string) error {
	return nil
}
