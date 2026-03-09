// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oidc

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"google.golang.org/protobuf/proto"
)

// Account must implement oplog.Replayable for upsertAccount to work
var _ oplog.ReplayableMessage = (*Account)(nil)

// Account must implement proto.Message for upsertAccount to work
var _ proto.Message = (*Account)(nil)

// upsertAccount will create/update account using claims from the user's ID and Access Tokens.
func (r *Repository) upsertAccount(ctx context.Context, am *AuthMethod, IdTokenClaims, AccessTokenClaims map[string]any) (*Account, error) {
	const op = "oidc.(Repository).upsertAccount"
	if am == nil || am.AuthMethod == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing auth method")
	}
	if IdTokenClaims == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing ID Token claims")
	}
	if AccessTokenClaims == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing Access Token claims")
	}

	fromSub, fromName, fromEmail := string(ToSubClaim), string(ToNameClaim), string(ToEmailClaim)
	if len(am.AccountClaimMaps) > 0 {
		acms, err := ParseAccountClaimMaps(ctx, am.AccountClaimMaps...)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		for _, m := range acms {
			toClaim, err := ConvertToAccountToClaim(ctx, m.To)
			if err != nil {
				return nil, errors.Wrap(ctx, err, op)
			}
			switch toClaim {
			case ToSubClaim:
				fromSub = m.From
			case ToEmailClaim:
				fromEmail = m.From
			case ToNameClaim:
				fromName = m.From
			default:
				// should never happen, but including it just in case.
				return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("%s=%s is not a valid account claim map", m.From, m.To))
			}
		}
	}

	var iss, sub string
	var ok bool
	if iss, ok = IdTokenClaims["iss"].(string); !ok {
		return nil, errors.New(ctx, errors.Unknown, op, "issuer is not present in ID Token, which should not be possible")
	}
	if sub, ok = IdTokenClaims[fromSub].(string); !ok {
		return nil, errors.New(ctx, errors.Unknown, op, fmt.Sprintf("mapping 'claim' %s to account subject and it is not present in ID Token", fromSub))
	}
	pubId, err := newAccountId(ctx, am.GetPublicId(), iss, sub)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	columns := []string{"public_id", "auth_method_id", "issuer", "subject"}
	values := []any{
		sql.Named("1", pubId),
		sql.Named("2", am.PublicId),
		sql.Named("3", iss),
		sql.Named("4", sub),
	}
	var conflictClauses, fieldMasks, nullMasks []string

	{
		marshaledTokenClaims, err := json.Marshal(IdTokenClaims)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		columns, values = append(columns, "token_claims"), append(values, sql.Named(fmt.Sprintf("%d", len(values)+1), string(marshaledTokenClaims)))
		conflictClauses = append(conflictClauses, fmt.Sprintf("token_claims = @%d", len(values)))
		fieldMasks = append(fieldMasks, TokenClaimsField)
	}
	{
		marshaledAccessTokenClaims, err := json.Marshal(AccessTokenClaims)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		columns, values = append(columns, "userinfo_claims"), append(values, sql.Named(fmt.Sprintf("%d", len(values)+1), string(marshaledAccessTokenClaims)))
		conflictClauses = append(conflictClauses, fmt.Sprintf("userinfo_claims = @%d", len(values)))
		fieldMasks = append(fieldMasks, UserinfoClaimsField)
	}

	issAsUrl, err := url.Parse(iss)
	if err != nil {
		return nil, errors.New(ctx, errors.Unknown, op, "unable to parse issuer", errors.WithWrap(err))
	}
	acctForOplog, err := NewAccount(ctx, am.PublicId, sub, WithIssuer(issAsUrl))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create new acct for oplog"))
	}

	var foundName any
	switch {
	case AccessTokenClaims[fromName] != nil:
		foundName = AccessTokenClaims[fromName]
		columns, values = append(columns, "full_name"), append(values, sql.Named(fmt.Sprintf("%d", len(values)+1), foundName))
	case IdTokenClaims[fromName] != nil:
		foundName = IdTokenClaims[fromName]
		columns, values = append(columns, "full_name"), append(values, sql.Named(fmt.Sprintf("%d", len(values)+1), foundName))
	}
	if foundName != nil {
		acctForOplog.FullName = foundName.(string)
		conflictClauses = append(conflictClauses, fmt.Sprintf("full_name = @%d", len(values)))
		fieldMasks = append(fieldMasks, NameField)
	} else {
		conflictClauses = append(conflictClauses, "full_name = NULL")
		nullMasks = append(nullMasks, NameField)
	}

	var foundEmail any
	switch {
	case AccessTokenClaims[fromEmail] != nil:
		foundEmail = AccessTokenClaims[fromEmail]
		columns, values = append(columns, "email"), append(values, sql.Named(fmt.Sprintf("%d", len(values)+1), foundEmail))
	case IdTokenClaims[fromEmail] != nil:
		foundEmail = IdTokenClaims[fromEmail]
		columns, values = append(columns, "email"), append(values, sql.Named(fmt.Sprintf("%d", len(values)+1), foundEmail))
	}
	if foundEmail != nil {
		acctForOplog.Email = foundEmail.(string)
		conflictClauses = append(conflictClauses, fmt.Sprintf("email = @%d", len(values)))
		fieldMasks = append(fieldMasks, "Email")
	} else {
		conflictClauses = append(conflictClauses, "email = NULL")
		nullMasks = append(nullMasks, "Email")
	}

	placeHolders := make([]string, 0, len(columns))
	for colNum := range columns {
		placeHolders = append(placeHolders, fmt.Sprintf("@%d", colNum+1))
	}
	query := fmt.Sprintf(acctUpsertQuery, strings.Join(columns, ", "), strings.Join(placeHolders, ", "), strings.Join(conflictClauses, ", "))

	oplogWrapper, err := r.kms.GetWrapper(ctx, am.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
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
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to insert/update auth oidc account"))
			}
			defer rows.Close()
			result := struct {
				PublicId string
				Version  int
			}{}
			var rowCnt int
			for rows.Next() {
				rowCnt += 1
				err = reader.ScanRows(ctx, rows, &result)
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to scan rows for account"))
				}
			}
			if err := rows.Err(); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get next rows for account"))
			}
			if rowCnt > 1 {
				return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("expected 1 row but got: %d", rowCnt))
			}
			if err := reader.LookupWhere(ctx, &updatedAcct, "auth_method_id = ? and issuer = ? and subject = ?", []any{am.PublicId, iss, sub}); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to look up auth oidc account for: %s / %s / %s", am.PublicId, iss, sub)))
			}
			// include the version incase of predictable account public ids based on a calculation using authmethod id and subject
			if result.Version == 1 && updatedAcct.PublicId == pubId {
				if err := upsertOplog(ctx, w, oplogWrapper, oplog.OpType_OP_TYPE_CREATE, am.ScopeId, updatedAcct, nil, nil); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to write create oplog for account"))
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
						return errors.Wrap(ctx, err, op, errors.WithMsg("unable to write update oplog for account"))
					}
				}
			}
			return nil
		},
	)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return updatedAcct, nil
}

// upsertOplog will write oplog msgs for account upserts. The db.Writer needs to be the writer for the current
// transaction that's executing the upsert. Both fieldMasks and nullMasks are allowed to be nil for update operations.
func upsertOplog(ctx context.Context, w db.Writer, oplogWrapper wrapping.Wrapper, operation oplog.OpType, scopeId string, acct *Account, fieldMasks, nullMasks []string) error {
	const op = "oidc.upsertOplog"
	if w == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing db writer")
	}
	if oplogWrapper == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing oplog wrapper")
	}
	if operation != oplog.OpType_OP_TYPE_CREATE && operation != oplog.OpType_OP_TYPE_UPDATE {
		return errors.New(ctx, errors.Internal, op, fmt.Sprintf("not a supported operation: %s", operation))
	}
	if scopeId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}
	if acct == nil || acct.Account == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing account")
	}
	if operation == oplog.OpType_OP_TYPE_UPDATE && len(fieldMasks) == 0 && len(nullMasks) == 0 {
		return errors.New(ctx, errors.InvalidParameter, op, "update operations must specify field masks and/or null masks")
	}
	ticket, err := w.GetTicket(ctx, acct)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket"))
	}
	metadata := acct.oplog(operation, scopeId)
	acctAsReplayable, ok := any(acct).(oplog.ReplayableMessage)
	if !ok {
		return errors.New(ctx, errors.Internal, op, "account is not replayable")
	}
	acctAsProto, ok := any(acct).(proto.Message)
	if !ok {
		return errors.New(ctx, errors.Internal, op, "account is not a proto message")
	}
	msg := oplog.Message{
		Message:        acctAsProto,
		TypeName:       acctAsReplayable.TableName(),
		OpType:         oplog.OpType_OP_TYPE_CREATE,
		FieldMaskPaths: fieldMasks,
		SetToNullPaths: nullMasks,
	}
	if err := w.WriteOplogEntryWith(ctx, oplogWrapper, ticket, metadata, []*oplog.Message{&msg}); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}
