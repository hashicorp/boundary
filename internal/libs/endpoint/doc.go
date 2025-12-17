// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package endpoint

// This package contains enpoint-related libraries.
//
// Currently, this consists only of a preference chooser that, given inputs of
// IP addresses/DNS names and a user-defined preference string, can select the
// most preferred endpoint to use. If no user-defined preference string is
// supplied, an endpoint is selected at random. Creating a preferencer will
// validate input, so calling NewPreferencer and ignoring the returned struct is
// a fine way to validate incoming preference order statements.
