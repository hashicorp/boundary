// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package errors

// Kind specifies the kind of error (unknown, parameter, integrity, etc).
type Kind uint32

const (
	Other Kind = iota
	Parameter
	Integrity
	Search
	Password
	Transaction
	Encryption
	Encoding
	State
	External
	VaultToken
	Configuration
)

func (e Kind) String() string {
	return map[Kind]string{
		Other:         "unknown",
		Parameter:     "parameter violation",
		Integrity:     "integrity violation",
		Search:        "search issue",
		Password:      "password violation",
		Transaction:   "db transaction issue",
		Encryption:    "encryption issue",
		Encoding:      "encoding issue",
		State:         "state violation",
		External:      "external system issue",
		VaultToken:    "vault token issue",
		Configuration: "configuration issue",
	}[e]
}
