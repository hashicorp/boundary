// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package handlers

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/hashicorp/boundary/internal/errors"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	authtokenpb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/authtokens"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
)

const (
	HttpOnlyCookieName       = "wt-http-token-cookie"
	JsVisibleCookieName      = "wt-js-token-cookie"
	tokenTypeField           = "type"
	finalRedirectUrlField    = "final_redirect_url"
	statusField              = "status"
	StatusCodeHeader         = "x-http-code"
	statusCodeMetadataHeader = "Grpc-Metadata-X-Http-Code"
)

// SetStatusCode allows a grpc service handler to set the outgoing http status
// code
func SetStatusCode(ctx context.Context, code int) error {
	const op = "handlers.SetHttpStatusCode"
	if http.StatusText(code) == "" {
		return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("unknown status code: %d", code))
	}
	if err := grpc.SetHeader(ctx, metadata.Pairs(StatusCodeHeader, strconv.Itoa(code))); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Internal))
	}
	return nil
}

// OutgoingResponseFilter is a gRPC gateway WithForwardResponseOption.  It's
// basically a filter that can manipulate the http response and has acesss to
// the outgoing proto msg
func OutgoingResponseFilter(ctx context.Context, w http.ResponseWriter, m proto.Message) error {
	const op = "handlers.OutgoingResponseFilter"

	if md, ok := runtime.ServerMetadataFromContext(ctx); ok {
		// set http status codes based on metadata set by the grpc service
		if statusCodes := md.HeaderMD.Get(StatusCodeHeader); len(statusCodes) > 0 {
			defer func() {
				// delete the headers to not expose any grpc-metadata in http response
				delete(md.HeaderMD, StatusCodeHeader)
				delete(w.Header(), statusCodeMetadataHeader)
			}()
			lastStatus, err := strconv.Atoi(statusCodes[len(statusCodes)-1])
			if err != nil {
				return fmt.Errorf("%s: unable to convert status code %s: %w", op, statusCodes[len(statusCodes)-1], err)
			}
			w.WriteHeader(lastStatus)
			return nil
		}
	}

	switch m := m.(type) {
	case *pbs.AuthenticateResponse:
		if m.GetAttributes() == nil || m.GetAttributes().GetFields() == nil {
			// We may not have a token depending on the subcommand; nothing to
			// do if there are no attributes
			return nil
		}
		fields := m.GetAttributes().GetFields()
		if m.GetCommand() == "token" {
			if _, ok := fields[statusField]; ok {
				// For now at least status will never be anything useful so
				// don't need to check on it; the mere presence is enough to
				// know what to do
				w.WriteHeader(http.StatusAccepted)
				return nil
			}
		}
		// It's a redirect
		if urlField, ok := fields[finalRedirectUrlField]; ok {
			u := urlField.GetStringValue()
			if u == "" {
				return fmt.Errorf("unable to convert final request url to string")
			}
			delete(fields, finalRedirectUrlField)
			w.Header().Set("Location", u)
			w.WriteHeader(http.StatusFound)
			return nil
		}
		// It's a token response
		if m.GetType() != "" {
			aToken := &authtokenpb.AuthToken{}
			// This may not be a token at all, so ignore unknown fields
			if err := StructToProto(m.GetAttributes(), aToken, WithDiscardUnknownFields(true)); err != nil {
				return err
			}
			tokenType := m.GetType()
			if strings.EqualFold(tokenType, "cookie") {
				tok := aToken.GetToken()
				if tok == "" {
					// Response did not include a token, continue
					return nil
				}
				delete(m.GetAttributes().GetFields(), "token")
				half := len(tok) / 2
				jsTok := http.Cookie{
					Name:  JsVisibleCookieName,
					Value: tok[:half],
					Path:  "/",
				}
				httpTok := http.Cookie{
					Name:     HttpOnlyCookieName,
					Value:    tok[half:],
					HttpOnly: true,
					Path:     "/",
				}
				http.SetCookie(w, &jsTok)
				http.SetCookie(w, &httpTok)
			}
		}
	}

	return nil
}
