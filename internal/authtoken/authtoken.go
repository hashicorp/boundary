// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package authtoken

import (
	"context"
	"fmt"
	mathrand "math/rand"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/authtoken/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/gen/controller/tokens"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/types/resource"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/extras/structwrapping"
	"github.com/hashicorp/go-secure-stdlib/base62"
	"github.com/mr-tron/base58"
	"google.golang.org/protobuf/proto"
)

// authTokenView is used for reading auth token's via the auth_token_account
// view which includes some columns from the auth_account table required by the
// API.  Defining a type allows us to easily override the tableName to use the
// view name.  authTokenViews share the same store struct/proto, which makes
// them easily convertable to vanilla AuthTokens when required.
type authTokenView struct {
	*store.AuthToken
	tableName string `gorm:"-"`
}

// allocAuthTokenView is just easier/better than leaking the underlying type
// bits to the repo, since the repo needs to alloc this type quite often.
func allocAuthTokenView() *authTokenView {
	fresh := &authTokenView{
		AuthToken: &store.AuthToken{},
	}
	return fresh
}

// toAuthToken converts the view type to the type returned to repo callers and
// the API.
func (atv *authTokenView) toAuthToken() *AuthToken {
	cp := proto.Clone(atv.AuthToken)
	return &AuthToken{
		AuthToken: cp.(*store.AuthToken),
	}
}

// A AuthToken contains auth tokens. It is owned by a scope.
type AuthToken struct {
	*store.AuthToken
	tableName string `gorm:"-"`
}

func (at *AuthToken) clone() *AuthToken {
	cp := proto.Clone(at.AuthToken)
	return &AuthToken{
		AuthToken: cp.(*store.AuthToken),
	}
}

// allocAuthToken is just easier/better than leaking the underlying type
// bits to the repo, since the repo needs to alloc this type quite often.
func allocAuthToken() *AuthToken {
	fresh := &AuthToken{
		AuthToken: &store.AuthToken{},
	}
	return fresh
}

// encrypt the entry's data using the provided cipher (wrapping.Wrapper)
func (at *AuthToken) encrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "authtoken.(writableAuthToken).encrypt"
	// structwrapping doesn't support embedding, so we'll pass in the store.Entry directly
	if err := structwrapping.WrapStruct(ctx, cipher, at.AuthToken, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt))
	}
	keyId, err := cipher.KeyId(ctx)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt), errors.WithMsg("unable to get cipher key id"))
	}
	at.KeyId = keyId
	return nil
}

// decrypt will decrypt the auth token's value using the provided cipher (wrapping.Wrapper)
func (at *AuthToken) decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "authtoken.(AuthToken).decrypt"
	// structwrapping doesn't support embedding, so we'll pass in the store.Entry directly
	if err := structwrapping.UnwrapStruct(ctx, cipher, at.AuthToken, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Decrypt))
	}
	return nil
}

const (
	// The version prefix is used to differentiate token versions just for future proofing.
	TokenValueVersionPrefix = "0"
	tokenLength             = 24
)

// NewAuthTokenId creates a new id for an auth token.
func NewAuthTokenId(ctx context.Context) (string, error) {
	const op = "authtoken.newAuthTokenId"
	id, err := db.NewPublicId(ctx, globals.AuthTokenPrefix)
	if err != nil {
		return "", errors.Wrap(ctx, err, op)
	}
	return id, nil
}

// newAuthToken generates a new in-memory token.  The WithStatus option is
// support and all other options are ignored.
func newAuthToken(ctx context.Context, opt ...Option) (*AuthToken, error) {
	const op = "authtoken.newAuthToken"
	token, err := base62.Random(tokenLength)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithCode(errors.Io))
	}
	opts := getOpts(opt...)

	return &AuthToken{
		AuthToken: &store.AuthToken{
			Token:  fmt.Sprintf("%s%s", TokenValueVersionPrefix, token),
			Status: string(opts.withStatus),
		},
	}, nil
}

// EncryptToken is a shared function for encrypting a token value for return to
// the user.
func EncryptToken(ctx context.Context, kmsCache *kms.Kms, scopeId, publicId, token string) (string, error) {
	const op = "authtoken.EncryptToken"
	r := mathrand.New(mathrand.NewSource(time.Now().UnixNano()))

	s1Info := &tokens.S1TokenInfo{
		Token:      token,
		Confounder: make([]byte, r.Intn(30)),
	}
	r.Read(s1Info.Confounder)

	marshaledS1Info, err := proto.Marshal(s1Info)
	if err != nil {
		return "", errors.Wrap(ctx, err, op, errors.WithMsg("marshaling encrypted token"), errors.WithCode(errors.Encode))
	}

	tokenWrapper, err := kmsCache.GetWrapper(ctx, scopeId, kms.KeyPurposeTokens)
	if err != nil {
		return "", errors.Wrap(ctx, err, op, errors.WithMsg("unable to get wrapper"))
	}

	blobInfo, err := tokenWrapper.Encrypt(ctx, []byte(marshaledS1Info), wrapping.WithAad([]byte(publicId)))
	if err != nil {
		return "", errors.Wrap(ctx, err, op, errors.WithMsg("marshaling token info"), errors.WithCode(errors.Encrypt))
	}

	marshaledBlob, err := proto.Marshal(blobInfo)
	if err != nil {
		return "", errors.Wrap(ctx, err, op, errors.WithMsg("marshaling encrypted token"), errors.WithCode(errors.Encode))
	}

	encoded := base58.FastBase58Encoding(marshaledBlob)

	return globals.ServiceTokenV1 + encoded, nil
}

// GetResourceType returns the resource type of the AuthToken
func (at AuthToken) GetResourceType() resource.Type {
	return resource.AuthToken
}

func (at AuthToken) GetUpdateTime() *timestamp.Timestamp {
	return at.UpdateTime
}

func (at AuthToken) GetCreateTime() *timestamp.Timestamp {
	return at.CreateTime
}

// GetDescription returns an empty string so that
// AuthToken will satisfy resource requirements
func (at AuthToken) GetDescription() string {
	return ""
}

// GetName returns an empty string so that
// AuthToken will satisfy resource requirements
func (at AuthToken) GetName() string {
	return ""
}

// GetVersion returns 0 so that
// AuthToken will satisfy resource requirements
func (at AuthToken) GetVersion() uint32 {
	return 0
}

type deletedAuthToken struct {
	PublicId   string `gorm:"primary_key"`
	DeleteTime *timestamp.Timestamp
}

// TableName returns the tablename to override the default gorm table name
func (at *deletedAuthToken) TableName() string {
	return "auth_token_deleted"
}
