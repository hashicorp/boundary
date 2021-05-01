package oidc

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"google.golang.org/protobuf/proto"
)

// Account must implement oplog.Replayable for upsertAccount to work
var _ oplog.ReplayableMessage = (*Account)(nil)

// Account must implement proto.Message for upsertAccount to work
var _ proto.Message = (*Account)(nil)

// upsertAccount will create/update account using claims from the user's ID and Access Tokens.
func (r *Repository) upsertAccount(ctx context.Context, am *AuthMethod, IdTokenClaims, AccessTokenClaims map[string]interface{}) (*Account, error) {
	const op = "oidc.(Repository).upsertAccount"
	if am == nil || am.AuthMethod == nil {
		return nil, errors.New(errors.InvalidParameter, op, "missing auth method")
	}
	if IdTokenClaims == nil {
		return nil, errors.New(errors.InvalidParameter, op, "missing ID Token claims")
	}
	if AccessTokenClaims == nil {
		return nil, errors.New(errors.InvalidParameter, op, "missing Access Token claims")
	}

	fromSub, fromName, fromEmail := "sub", "name", "email"
	if len(am.AccountClaimMaps) > 0 {
		acms, err := ParseAccountClaimMaps(am.AccountClaimMaps...)
		if err != nil {
			return nil, errors.Wrap(err, op)
		}
		for from, to := range acms {
			toClaim, err := ConvertToAccountToClaim(to)
			if err != nil {
				return nil, errors.Wrap(err, op)
			}
			switch toClaim {
			case ToSubClaim:
				fromSub = from
			case ToEmailClaim:
				fromEmail = from
			case ToNameClaim:
				fromName = from
			default:
				// should never happen, but including it just in case.
				return nil, errors.New(errors.InvalidParameter, op, fmt.Sprintf("%s=%s is not a valid account claim map", from, to))
			}
		}
	}

	var iss, sub string
	var ok bool
	if iss, ok = IdTokenClaims["iss"].(string); !ok {
		return nil, errors.New(errors.Unknown, op, "issuer is not present in ID Token, which should not be possible")
	}
	if sub, ok = IdTokenClaims[fromSub].(string); !ok {
		return nil, errors.New(errors.Unknown, op, fmt.Sprintf("mapping 'claim' %s to account subject and it is not present in ID Token", fromSub))
	}
	pubId, err := newAccountId(am.GetPublicId(), iss, sub)
	if err != nil {
		return nil, errors.Wrap(err, op)
	}

	columns := []string{"public_id", "auth_method_id", "issuer", "subject"}
	values := []interface{}{pubId, am.PublicId, iss, sub}
	var conflictClauses, fieldMasks, nullMasks []string

	var foundEmail, foundName interface{}
	switch {
	case AccessTokenClaims[fromName] != nil:
		foundName = AccessTokenClaims[fromName]
		columns, values = append(columns, "full_name"), append(values, foundName)
	case IdTokenClaims[fromName] != nil:
		foundName = IdTokenClaims[fromName]
		columns, values = append(columns, "full_name"), append(values, foundName)
	default:
		conflictClauses = append(conflictClauses, "full_name = NULL")
		nullMasks = append(nullMasks, NameField)
	}
	switch {
	case AccessTokenClaims[fromEmail] != nil:
		foundEmail = AccessTokenClaims[fromEmail]
		columns, values = append(columns, "email"), append(values, foundEmail)
	case IdTokenClaims[fromEmail] != nil:
		foundEmail = IdTokenClaims[fromEmail]
		columns, values = append(columns, "email"), append(values, foundEmail)
	default:
		conflictClauses = append(conflictClauses, "email = NULL")
		nullMasks = append(nullMasks, "Email")
	}

	if foundName != nil {
		values = append(values, foundName)
		conflictClauses = append(conflictClauses, fmt.Sprintf("full_name = $%d", len(values)))
		fieldMasks = append(fieldMasks, NameField)
	}
	if foundEmail != nil {
		values = append(values, foundEmail)
		conflictClauses = append(conflictClauses, fmt.Sprintf("email = $%d", len(values)))
		fieldMasks = append(fieldMasks, "Email")
	}

	issAsUrl, err := url.Parse(iss)
	if err != nil {
		return nil, errors.New(errors.Unknown, op, "unable to parse issuer", errors.WithWrap(err))
	}
	acctForOplog, err := NewAccount(am.PublicId, sub, WithIssuer(issAsUrl))
	if err != nil {
		return nil, errors.Wrap(err, op, errors.WithMsg("unable to create new acct for oplog"))
	}

	if foundName != nil {
		acctForOplog.FullName = foundName.(string)
	}
	if foundEmail != nil {
		acctForOplog.Email = foundEmail.(string)
	}

	placeHolders := make([]string, 0, len(columns))
	for colNum := range columns {
		placeHolders = append(placeHolders, fmt.Sprintf("$%d", colNum+1))
	}
	query := fmt.Sprintf(acctUpsertQuery, strings.Join(columns, ", "), strings.Join(placeHolders, ", "), strings.Join(conflictClauses, ", "))

	oplogWrapper, err := r.kms.GetWrapper(ctx, am.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	updatedAcct := AllocAccount()
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			var err error
			rows, err := w.Query(ctx, query, values)
			if err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to insert/update auth oidc account"))
			}
			defer rows.Close()
			result := struct {
				PublicId string
				Version  int
			}{}
			var rowCnt int
			for rows.Next() {
				rowCnt += 1
				err = r.reader.ScanRows(rows, &result)
				if err != nil {
					return errors.Wrap(err, op, errors.WithMsg("unable to scan rows for account"))
				}
			}
			if rowCnt > 1 {
				return errors.New(errors.MultipleRecords, op, fmt.Sprintf("expected 1 row but got: %d", rowCnt))
			}
			if err := reader.LookupWhere(ctx, &updatedAcct, "auth_method_id = ? and issuer = ? and subject = ?", am.PublicId, iss, sub); err != nil {
				return errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("unable to look up auth oidc account for: %s / %s / %s", am.PublicId, iss, sub)))
			}
			// include the version incase of predictable account public ids based on a calculation using authmethod id and subject
			if result.Version == 1 && updatedAcct.PublicId == pubId {
				if err := upsertOplog(ctx, w, oplogWrapper, oplog.OpType_OP_TYPE_CREATE, am.ScopeId, updatedAcct, nil, nil); err != nil {
					return errors.Wrap(err, op, errors.WithMsg("unable to write create oplog for account"))
				}
			} else {
				if len(fieldMasks) > 0 || len(nullMasks) > 0 {
					acctForOplog := AllocAccount()
					acctForOplog.PublicId = updatedAcct.PublicId
					if foundEmail != nil {
						acctForOplog.Email = foundEmail.(string)
					}
					if foundName != nil {
						acctForOplog.FullName = foundName.(string)
					}
					if err := upsertOplog(ctx, w, oplogWrapper, oplog.OpType_OP_TYPE_UPDATE, am.ScopeId, acctForOplog, fieldMasks, nullMasks); err != nil {
						return errors.Wrap(err, op, errors.WithMsg("unable to write update oplog for account"))
					}
				}
			}
			return nil
		},
	)
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	return updatedAcct, nil
}

// upsertOplog will write oplog msgs for account upserts. The db.Writer needs to be the writer for the current
// transaction that's executing the upsert. Both fieldMasks and nullMasks are allowed to be nil for update operations.
func upsertOplog(ctx context.Context, w db.Writer, oplogWrapper wrapping.Wrapper, operation oplog.OpType, scopeId string, acct *Account, fieldMasks, nullMasks []string) error {
	const op = "oidc.upsertOplog"
	if w == nil {
		return errors.New(errors.InvalidParameter, op, "missing db writer")
	}
	if oplogWrapper == nil {
		return errors.New(errors.InvalidParameter, op, "missing oplog wrapper")
	}
	if operation != oplog.OpType_OP_TYPE_CREATE && operation != oplog.OpType_OP_TYPE_UPDATE {
		return errors.New(errors.Internal, op, fmt.Sprintf("not a supported operation: %s", operation))
	}
	if scopeId == "" {
		return errors.New(errors.InvalidParameter, op, "missing scope id")
	}
	if acct == nil || acct.Account == nil {
		return errors.New(errors.InvalidParameter, op, "missing account")
	}
	if operation == oplog.OpType_OP_TYPE_UPDATE && len(fieldMasks) == 0 && len(nullMasks) == 0 {
		return errors.New(errors.InvalidParameter, op, "update operations must specify field masks and/or null masks")
	}
	ticket, err := w.GetTicket(acct)
	if err != nil {
		return errors.Wrap(err, op, errors.WithMsg("unable to get ticket"))
	}
	metadata := acct.oplog(operation, scopeId)
	acctAsReplayable, ok := interface{}(acct).(oplog.ReplayableMessage)
	if !ok {
		return errors.New(errors.Internal, op, "account is not replayable")
	}
	acctAsProto, ok := interface{}(acct).(proto.Message)
	if !ok {
		return errors.New(errors.Internal, op, "account is not a proto message")
	}
	msg := oplog.Message{
		Message:        acctAsProto,
		TypeName:       acctAsReplayable.TableName(),
		OpType:         oplog.OpType_OP_TYPE_CREATE,
		FieldMaskPaths: fieldMasks,
		SetToNullPaths: nullMasks,
	}
	if err := w.WriteOplogEntryWith(ctx, oplogWrapper, ticket, metadata, []*oplog.Message{&msg}); err != nil {
		return errors.Wrap(err, op)
	}
	return nil
}
