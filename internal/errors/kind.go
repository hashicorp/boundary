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
)

func (e Kind) String() string {
	return map[Kind]string{
		Other:       "unknown",
		Parameter:   "parameter violation",
		Integrity:   "integrity violation",
		Search:      "search issue",
		Password:    "password violation",
		Transaction: "db transaction issue",
		Encryption:  "encryption issue",
		Encoding:    "encoding issue",
		State:       "state violation",
		External:    "external system issue",
		VaultToken:  "vault token issue",
	}[e]
}
