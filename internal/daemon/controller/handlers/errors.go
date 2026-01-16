// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package handlers

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/event"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api"
	pberrors "github.com/hashicorp/boundary/internal/gen/errors"
	"github.com/mr-tron/base58"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const (
	genericUniquenessMsg = "Invalid request.  Request attempted to make second resource with the same field value that must be unique."
	genericNotFoundMsg   = "Unable to find requested resource."

	// domainErrHeader defines an http header for encoded domain errors from the
	// grpc server.
	domainErrHeader = "x-domain-err"
	// domainErrMetadataHeader defines an http header for encoded domain errors from the
	// grpc server via metadata
	domainErrMetadataHeader = "Grpc-Metadata-X-Domain-Err"

	apiErrHeader         = "x-api-err"
	apiErrMetadataHeader = "Grpc-Metadata-X-Api-Err"
)

type ApiError struct {
	Status int32
	Inner  *pb.Error
}

func (e *ApiError) Error() string {
	res := fmt.Sprintf("Status: %d, Kind: %q, Error: %q", e.Status, e.Inner.GetKind(), e.Inner.GetMessage())
	var dets []string
	for _, rf := range e.Inner.GetDetails().GetRequestFields() {
		dets = append(dets, fmt.Sprintf("{name: %q, desc: %q}", rf.GetName(), rf.GetDescription()))
	}
	if len(dets) > 0 {
		det := strings.Join(dets, ", ")
		res = fmt.Sprintf("%s, Details: {%s}", res, det)
	}
	return res
}

func (e *ApiError) Is(target error) bool {
	var tApiErr *ApiError
	if !errors.As(target, &tApiErr) {
		return false
	}
	return tApiErr.Inner.Kind == e.Inner.Kind && tApiErr.Status == e.Status
}

// ApiErrorWithCode returns an api error with the provided code.
func ApiErrorWithCode(c codes.Code) error {
	return &ApiError{
		Status: int32(runtime.HTTPStatusFromCode(c)),
		Inner: &pb.Error{
			Kind: c.String(),
		},
	}
}

// ApiErrorWithCodeAndMessage returns an api error with the provided code and message.
func ApiErrorWithCodeAndMessage(c codes.Code, msg string, args ...any) error {
	if len(args) > 0 {
		msg = fmt.Sprintf(msg, args...)
	}
	return &ApiError{
		Status: int32(runtime.HTTPStatusFromCode(c)),
		Inner: &pb.Error{
			Kind:    c.String(),
			Message: msg,
		},
	}
}

// NotFoundError returns an ApiError indicating a resource couldn't be found.
func NotFoundError() error {
	return &ApiError{
		Status: http.StatusNotFound,
		Inner: &pb.Error{
			Kind:    codes.NotFound.String(),
			Message: "Resource not found.",
		},
	}
}

// NotFoundErrorf returns an ApiError indicating a resource couldn't be found.
func NotFoundErrorf(msg string, a ...any) *ApiError {
	return &ApiError{
		Status: http.StatusNotFound,
		Inner: &pb.Error{
			Kind:    codes.NotFound.String(),
			Message: fmt.Sprintf(msg, a...),
		},
	}
}

var unauthorizedError = &ApiError{
	Status: http.StatusForbidden,
	Inner: &pb.Error{
		Kind:    codes.PermissionDenied.String(),
		Message: "Forbidden.",
	},
}

func ForbiddenError() error {
	return unauthorizedError
}

var unauthenticatedError = &ApiError{
	Status: http.StatusUnauthorized,
	Inner: &pb.Error{
		Kind:    codes.Unauthenticated.String(),
		Message: "Unauthenticated, or invalid token.",
	},
}

func UnauthenticatedError() error {
	return unauthenticatedError
}

func InvalidArgumentErrorf(msg string, fields map[string]string) *ApiError {
	const op = "handlers.InvalidArgumentErrorf"
	ctx := context.TODO()
	err := ApiErrorWithCodeAndMessage(codes.InvalidArgument, msg)
	var apiErr *ApiError
	if !errors.As(err, &apiErr) {
		event.WriteError(ctx, op, err, event.WithInfoMsg("Unable to build invalid argument api error."))
	}

	if len(fields) > 0 {
		apiErr.Inner.Details = &pb.ErrorDetails{}
	}
	for k, v := range fields {
		apiErr.Inner.Details.RequestFields = append(apiErr.Inner.Details.RequestFields, &pb.FieldError{Name: k, Description: v})
	}
	sort.Slice(apiErr.Inner.GetDetails().GetRequestFields(), func(i, j int) bool {
		return apiErr.Inner.Details.RequestFields[i].GetName() < apiErr.Inner.Details.RequestFields[j].GetName()
	})
	return apiErr
}

func invalidListTokenError(err error) *ApiError {
	const op = "handlers.invalidListTokenError"
	ctx := context.TODO()

	var domainErr *errors.Err
	if !errors.As(err, &domainErr) {
		event.WriteError(ctx, op, err, event.WithInfoMsg("Unable to build invalid list token api error."))
	}

	return &ApiError{
		Status: http.StatusBadRequest,
		Inner: &pb.Error{
			Kind:    domainErr.Info().Message,
			Op:      string(domainErr.Op),
			Message: domainErr.Msg,
		},
	}
}

// ConflictErrorf generates an ApiErr when a pre-conditional check is violated.
// Note, this deliberately doesn't translate to the similarly named '412
// Precondition Failed' HTTP response status. The ApiErr returned is a 400 bad
// request because this is how the grpc-gateway mapping is implemented for
// failed precondition protobuf errors.
func ConflictErrorf(msg string) *ApiError {
	const op = "handlers.ConflictErrorf"
	ctx := context.TODO()
	err := ApiErrorWithCodeAndMessage(codes.FailedPrecondition, msg)
	var apiErr *ApiError
	if !errors.As(err, &apiErr) {
		event.WriteError(ctx, op, err, event.WithInfoMsg("Unable to build conflict api error."))
	}
	return apiErr
}

var statusRegEx = regexp.MustCompile("Status: ([0-9]+), Kind: \"(.*)\", Error: \"(.*)\"")

// Converts a known errors into an error that can presented to an end user over the API.
func backendErrorToApiError(inErr error) *ApiError {
	stErr := status.Convert(inErr)

	switch {
	case errors.Is(inErr, runtime.ErrNotMatch):
		// grpc gateway uses this error when the path was not matched, but the error uses codes.Unimplemented which doesn't match the intention.
		// Overwrite the error to match our expected behavior.
		return &ApiError{
			Status: http.StatusNotFound,
			Inner: &pb.Error{
				Kind:    codes.NotFound.String(),
				Message: http.StatusText(http.StatusNotFound),
			},
		}
	case status.Code(inErr) == codes.Unimplemented:
		// Instead of returning a 501 we always want to return a 405 when a method isn't implemented.
		return &ApiError{
			Status: http.StatusMethodNotAllowed,
			Inner: &pb.Error{
				Kind:    codes.Unimplemented.String(),
				Message: stErr.Message(),
			},
		}
	case errors.Match(errors.T(errors.RecordNotFound), inErr):
		return NotFoundErrorf(genericNotFoundMsg)
	case errors.Match(errors.T(errors.AccountAlreadyAssociated), inErr):
		return InvalidArgumentErrorf(inErr.Error(), nil)
	case errors.Match(errors.T(errors.InvalidListToken), inErr):
		return invalidListTokenError(inErr)
	case errors.Match(errors.T(errors.InvalidFieldMask), inErr), errors.Match(errors.T(errors.EmptyFieldMask), inErr):
		return InvalidArgumentErrorf("Error in provided request", map[string]string{"update_mask": "Invalid update mask provided."})
	case errors.IsUniqueError(inErr):
		return InvalidArgumentErrorf(genericUniquenessMsg, nil)
	case errors.IsConflictError(inErr):
		return ConflictErrorf(inErr.Error())
	}

	var statusCode int32 = http.StatusInternalServerError
	var domainErr *errors.Err
	if errors.As(inErr, &domainErr) && domainErr.Code >= 400 && domainErr.Code <= 599 {
		// Domain error codes 400-599 align with http client and server error codes, use the domain error code instead of 500
		statusCode = int32(domainErr.Code)
	}

	// perhaps the error is from the grpc gateway, so match against the known
	// apiError msg format.
	if found := statusRegEx.FindStringSubmatch(stErr.Message()); len(found) == 4 {
		u32, err := strconv.ParseInt(found[1], 10, 32)
		if err == nil { // notice it's testing for NO err
			return &ApiError{
				Status: int32(u32),
				Inner:  &pb.Error{Kind: found[2], Message: found[3]},
			}
		}
	}

	// TODO: Don't return potentially sensitive information (like which user id an account
	//  is already associated with when attempting to re-associate it).
	return &ApiError{
		Status: statusCode,
		Inner:  &pb.Error{Kind: codes.Internal.String(), Message: inErr.Error()},
	}
}

func ErrorHandler() runtime.ErrorHandlerFunc {
	const op = "handlers.ErrorHandler"
	const errorFallback = `{"error": "failed to marshal error message"}`
	return func(ctx context.Context, _ *runtime.ServeMux, mar runtime.Marshaler, w http.ResponseWriter, r *http.Request, inErr error) {
		// API specified error, otherwise we need to translate repo/db errors.

		// the grpc server will encoded domain errors into the x-domain-err, so
		// let's check there first. (see: controller.errorInterceptor)
		md, ok := runtime.ServerMetadataFromContext(ctx)
		if ok {
			defer func() {
				// make sure we don't leak the headers that were used as a comm
				// channel between the grpc server and the http proxy
				delete(md.HeaderMD, domainErrHeader)
				delete(w.Header(), domainErrMetadataHeader)

				delete(md.HeaderMD, apiErrHeader)
				delete(w.Header(), apiErrMetadataHeader)
			}()
			domainErrHdrs := md.HeaderMD.Get(domainErrHeader)
			apiErrHdrs := md.HeaderMD.Get(apiErrHeader)

			switch {
			case len(domainErrHdrs) > 0:
				decoded, err := base58.FastBase58Decoding(domainErrHdrs[0])
				if err != nil {
					event.WriteError(ctx, op, err, event.WithInfoMsg("failed to decode domain err header"))
					w.WriteHeader(http.StatusInternalServerError)
					if _, err := io.WriteString(w, errorFallback); err != nil {
						event.WriteError(ctx, op, err, event.WithInfoMsg("failed to write response"))
					}
					return
				}
				var pbErr pberrors.Err
				if err := proto.Unmarshal(decoded, &pbErr); err != nil {
					event.WriteError(ctx, op, err, event.WithInfoMsg("failed to marshal domain err header"))
					w.WriteHeader(http.StatusInternalServerError)
					if _, err := io.WriteString(w, errorFallback); err != nil {
						event.WriteError(ctx, op, err, event.WithInfoMsg("failed to write response"))
					}
					return
				}
				inErr = errors.FromPbErrors(&pbErr)
			case len(apiErrHdrs) > 0:
				decoded, err := base58.FastBase58Decoding(apiErrHdrs[0])
				if err != nil {
					event.WriteError(ctx, op, err, event.WithInfoMsg("failed to decode api err header"))
					w.WriteHeader(http.StatusInternalServerError)
					if _, err := io.WriteString(w, errorFallback); err != nil {
						event.WriteError(ctx, op, err, event.WithInfoMsg("failed to write response"))
					}
					return
				}
				var pbApiErr pberrors.ApiError
				if err := proto.Unmarshal(decoded, &pbApiErr); err != nil {
					event.WriteError(ctx, op, err, event.WithInfoMsg("failed to marshal api err header"))
					w.WriteHeader(http.StatusInternalServerError)
					if _, err := io.WriteString(w, errorFallback); err != nil {
						event.WriteError(ctx, op, err, event.WithInfoMsg("failed to write response"))
					}
					return
				}
				inErr = &ApiError{
					Status: pbApiErr.Status,
					Inner:  pbApiErr.ApiError,
				}
			}
		}
		var apiErr *ApiError
		isApiErr := errors.As(inErr, &apiErr)
		if !isApiErr {
			if err := backendErrorToApiError(inErr); err != nil && !errors.As(err, &apiErr) {
				event.WriteError(ctx, op, err, event.WithInfoMsg("failed to cast error to api error"))
			}
		}

		if apiErr.Status == http.StatusInternalServerError {
			event.WriteError(ctx, op, inErr, event.WithInfoMsg("internal error returned"))
		}

		buf, merr := mar.Marshal(apiErr.Inner)
		if merr != nil {
			event.WriteError(ctx, op, merr, event.WithInfoMsg("failed to marshal error response", "response", fmt.Sprintf("%#v", apiErr.Inner)))
			w.WriteHeader(http.StatusInternalServerError)
			if _, err := io.WriteString(w, errorFallback); err != nil {
				event.WriteError(ctx, op, err, event.WithInfoMsg("failed to write response"))
			}
			return
		}

		w.Header().Set("Content-Type", mar.ContentType(apiErr.Inner))
		w.WriteHeader(int(apiErr.Status))
		if _, err := w.Write(buf); err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("failed to send response chunk"))
			return
		}
	}
}

func ToApiError(e error) *pb.Error {
	return backendErrorToApiError(e).Inner
}
