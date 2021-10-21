package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

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
	issAsUrl, err := url.Parse(iss)
	if err != nil {
		return nil, errors.New(ctx, errors.Unknown, op, "unable to parse issuer", errors.WithWrap(err))
	}

	acct := AllocAccount()
	acct.PublicId = pubId
	acct.AuthMethodId = am.PublicId
	acct.Issuer = issAsUrl.String()
	acct.Subject = sub

	oc := db.OnConflict{
		Target: db.Constraint("auth_oidc_account_auth_method_id_issuer_subject_uq"),
		Action: db.SetColumns([]string{"public_id", "auth_method_id", "issuer", "subject", "userinfo_claims", "token_claims"}),
	}

	marshaledTokenClaims, err := json.Marshal(IdTokenClaims)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	acct.TokenClaims = string(marshaledTokenClaims)

	marshaledAccessTokenClaims, err := json.Marshal(AccessTokenClaims)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	acct.UserinfoClaims = string(marshaledAccessTokenClaims)

	var foundName, foundEmail bool
	switch {
	case AccessTokenClaims[fromName] != nil:
		foundName = true
		acct.FullName = AccessTokenClaims[fromName].(string)
	case IdTokenClaims[fromName] != nil:
		foundName = true
		acct.FullName = IdTokenClaims[fromName].(string)
	}

	switch {
	case AccessTokenClaims[fromEmail] != nil:
		foundEmail = true
		acct.Email = AccessTokenClaims[fromEmail].(string)
	case IdTokenClaims[fromEmail] != nil:
		foundEmail = true
		acct.Email = IdTokenClaims[fromEmail].(string)
	}
	if foundName {
		oc.Action = append(oc.Action.([]db.ColumnValue), db.SetColumns([]string{"full_name"})...)
	}
	if foundEmail {
		oc.Action = append(oc.Action.([]db.ColumnValue), db.SetColumns([]string{"email"})...)
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, am.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			var rowCnt int64
			err := w.Create(ctx, acct, db.WithOnConflict(&oc), db.WithReturnRowsAffected(&rowCnt), db.WithOplog(oplogWrapper, acct.oplog(oplog.OpType_OP_TYPE_CREATE, am.ScopeId)))
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to insert/update auth oidc account"))
			}
			if rowCnt > 1 {
				return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("expected 1 row but got: %d", rowCnt))
			}
			return nil
		},
	)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return acct, nil
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
	ticket, err := w.GetTicket(acct)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket"))
	}
	metadata := acct.oplog(operation, scopeId)
	acctAsReplayable, ok := interface{}(acct).(oplog.ReplayableMessage)
	if !ok {
		return errors.New(ctx, errors.Internal, op, "account is not replayable")
	}
	acctAsProto, ok := interface{}(acct).(proto.Message)
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
