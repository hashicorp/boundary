// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package template

// Data is the top-level struct containing the various domains of templated
// data. The Generate function can take in any data but this provides a shared
// structure for general use.
type Data struct {
	User    User
	Account Account
}

// User contains user information. FullName and Email are not always populated
// or may be different than the values in the Account struct; these are set on
// the user by an account from the primary auth method in a scope. It is
// possible for a user to not have an account from that auth method (in which
// case it will not be populated), or for the token they have used for the
// request to be from a different auth method, in which case it may not match
// what's in the Account struct.
type User struct {
	Id        *string
	Name      *string
	LoginName *string
	FullName  *string
	Email     *string
}

// Account contains account information. Not all fields will always be
// populated; it depends on the type of account.
type Account struct {
	Id        *string
	Name      *string
	LoginName *string
	Subject   *string
	Email     *string
}
