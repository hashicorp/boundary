package oidc

import (
	"github.com/hashicorp/boundary/internal/auth/oidc/store"
	"github.com/hashicorp/boundary/internal/errors"
	"google.golang.org/protobuf/proto"
)

const (
	// defaultAcctClaimMapTableName defines the default table name for an AccountClaimMap
	defaultAcctClaimMapTableName = "auth_oidc_account_claim_map"
)

type AccountToClaim string

const (
	ToSubClaim   AccountToClaim = "sub"
	ToEmailClaim AccountToClaim = "email"
	ToNameClaim  AccountToClaim = "name"
)

// AccountClaimMap defines optional OIDC scope values that are used to request
// claims, in addition to the default scope of "openid" (see: DefaultClaimsScope).
type AccountClaimMap struct {
	*store.AccountClaimMap
	tableName string
}

func NewAccountClaimMap(authMethodId, fromClaim string, toClaim AccountToClaim) (*AccountClaimMap, error) {
	const op = "oidc.NewAccountClaimMap"
	cs := &AccountClaimMap{
		AccountClaimMap: &store.AccountClaimMap{
			OidcMethodId: authMethodId,
			FromClaim:    fromClaim,
			ToClaim:      string(toClaim),
		},
	}
	if err := cs.validate(op); err != nil {
		return nil, err
	}
	return cs, nil
}

// validate the AccountClaimMap.  On success, it will return nil.
func (cs *AccountClaimMap) validate(caller errors.Op) error {
	if cs.OidcMethodId == "" {
		return errors.New(errors.InvalidParameter, caller, "missing oidc auth method id")
	}
	if cs.FromClaim == "" {
		return errors.New(errors.InvalidParameter, caller, "missing from claim")
	}
	switch cs.ToClaim {
	case "":
		return errors.New(errors.InvalidParameter, caller, "missing to claim")
	case "sub", "email", "profile":
	default:
	}
	return nil
}

// AllocClaimsScope makes an empty one in memory
func AllocAccountClaimMap() AccountClaimMap {
	return AccountClaimMap{
		AccountClaimMap: &store.AccountClaimMap{},
	}
}

// Clone a AccountClaimMap
func (cs *AccountClaimMap) Clone() *AccountClaimMap {
	cp := proto.Clone(cs.AccountClaimMap)
	return &AccountClaimMap{
		AccountClaimMap: cp.(*store.AccountClaimMap),
	}
}

// TableName returns the table name.
func (s *AccountClaimMap) TableName() string {
	if s.tableName != "" {
		return s.tableName
	}
	return defaultAcctClaimMapTableName
}

// SetTableName sets the table name.
func (s *AccountClaimMap) SetTableName(n string) {
	s.tableName = n
}
