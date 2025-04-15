// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controller

import (
	"context"
	"fmt"
	"math"
	"net"
	"net/http"
	"regexp"
	"strings"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_recovery "github.com/grpc-ecosystem/go-grpc-middleware/recovery"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/daemon/controller/common"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/types/subtypes"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/go-version"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
)

const (
	gatewayTarget = ""

	// userAgentsKey defines the user-agent header key for the gRPC gateway
	userAgentsKey = "userAgents"
)

// Regular expression to parse user-agent product, version, and comments
var userAgentRegex = regexp.MustCompile(`(?P<product>[^\s/()]+)/(?P<version>[^\s()]+)(?: \((?P<comments>[^)]+)\))?`)

type grpcServerListener interface {
	net.Listener
	Dial() (net.Conn, error)
}

func gatewayDialOptions(lis grpcServerListener) []grpc.DialOption {
	return []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(math.MaxInt32)),
		grpc.WithDefaultCallOptions(grpc.MaxCallSendMsgSize(math.MaxInt32)),
	}
}

type noDelimiterStreamingMarshaler struct {
	runtime.Marshaler
}

func (noDelimiterStreamingMarshaler) Delimiter() []byte {
	return nil
}

func newGrpcGatewayMux() *runtime.ServeMux {
	return runtime.NewServeMux(
		runtime.WithMetadata(correlationIdAnnotator),
		runtime.WithMetadata(userAgentHeadersAnnotator),
		runtime.WithMarshalerOption(runtime.MIMEWildcard, &noDelimiterStreamingMarshaler{
			&runtime.HTTPBodyMarshaler{
				Marshaler: handlers.JSONMarshaler(),
			},
		}),
		runtime.WithErrorHandler(handlers.ErrorHandler()),
		runtime.WithForwardResponseOption(handlers.OutgoingResponseFilter),
		runtime.WithDisablePathLengthFallback(),
	)
}

func correlationIdAnnotator(_ context.Context, req *http.Request) metadata.MD {
	var correlationId string
	for k, v := range req.Header {
		if strings.ToLower(k) == globals.CorrelationIdKey {
			correlationId = v[0]
			break
		}
	}
	if correlationId == "" {
		var err error
		correlationId, err = uuid.GenerateUUID()

		// GenerateUUID should not return an error. If it does, panic since there is no
		// err return path here.
		if err != nil {
			panic(fmt.Sprintf("failed to generate correlation id: %v", err))
		}
	}

	return metadata.New(map[string]string{
		globals.CorrelationIdKey: correlationId,
	})
}

func userAgentHeadersAnnotator(_ context.Context, req *http.Request) metadata.MD {
	userAgent := req.Header.Get("User-Agent")
	if userAgent == "" {
		return metadata.MD{}
	}
	matches := userAgentRegex.FindAllStringSubmatch(userAgent, -1)

	var userAgents []*event.UserAgent
	for _, match := range matches {
		product := strings.TrimSpace(match[1])
		agentVersion := strings.TrimSpace(match[2])

		if strings.HasPrefix(agentVersion, "v") {
			// Invalid version format (starting with 'v')
			continue
		}
		if _, err := version.NewSemver(agentVersion); err != nil {
			// Invalid version
			continue
		}

		agentData := &event.UserAgent{
			Product:        product,
			ProductVersion: agentVersion,
		}

		if len(match) > 3 && match[3] != "" {
			// Clean up and split comments
			commentsRaw := strings.Split(match[3], ";")
			var comments []string
			for _, c := range commentsRaw {
				if trimmed := strings.TrimSpace(c); trimmed != "" {
					comments = append(comments, trimmed)
				}
			}
			if len(comments) > 0 {
				agentData.Comments = comments
			}
		}

		userAgents = append(userAgents, agentData)
	}

	if len(userAgents) == 0 {
		return metadata.MD{}
	}
	userAgentJSON, err := handlers.JSONMarshaler().Marshal(userAgents)
	if err != nil {
		return metadata.MD{}
	}
	return metadata.New(map[string]string{
		userAgentsKey: string(userAgentJSON),
	})
}

// newGrpcServerListener will create an in-memory listener for the gRPC server.
func newGrpcServerListener() grpcServerListener {
	buffer := globals.DefaultMaxRequestSize // seems like a reasonable size for the ring buffer, but then happily change the size if more info becomes available
	return bufconn.Listen(int(buffer))
}

func newGrpcServer(
	ctx context.Context,
	iamRepoFn common.IamRepoFactory,
	authTokenRepoFn common.AuthTokenRepoFactory,
	serversRepoFn common.ServersRepoFactory,
	passwordAuthRepoFn common.PasswordAuthRepoFactory,
	oidcAuthRepoFn common.OidcAuthRepoFactory,
	ldapAuthRepoFn common.LdapAuthRepoFactory,
	aliasRepoFn common.AliasRepoFactory,
	kms *kms.Kms,
	eventer *event.Eventer,
) (*grpc.Server, string, error) {
	const op = "controller.newGrpcServer"
	ticket, err := db.NewPrivateId(ctx, "gwticket")
	if err != nil {
		return nil, "", errors.Wrap(ctx, err, op, errors.WithMsg("unable to generate gateway ticket"))
	}
	unaryCtxInterceptor, err := requestCtxUnaryInterceptor(ctx, iamRepoFn, authTokenRepoFn, serversRepoFn, passwordAuthRepoFn, oidcAuthRepoFn, ldapAuthRepoFn, kms, ticket, eventer)
	if err != nil {
		return nil, "", err
	}

	streamCtxInterceptor, err := requestCtxStreamInterceptor(
		ctx,
		iamRepoFn,
		authTokenRepoFn,
		serversRepoFn,
		passwordAuthRepoFn,
		oidcAuthRepoFn,
		ldapAuthRepoFn,
		kms,
		ticket,
		eventer,
	)
	if err != nil {
		return nil, "", err
	}
	return grpc.NewServer(
		grpc.MaxRecvMsgSize(math.MaxInt32),
		grpc.MaxSendMsgSize(math.MaxInt32),
		grpc.StreamInterceptor(
			grpc_middleware.ChainStreamServer(
				streamCtxInterceptor,
			),
		),
		grpc.UnaryInterceptor(
			grpc_middleware.ChainUnaryServer(
				unaryCtxInterceptor,                           // populated requestInfo from headers into the request ctx
				correlationIdInterceptor(ctx),                 // populate correlationId from headers or generate random id
				errorInterceptor(ctx),                         // convert domain and api errors into headers for the http proxy
				aliasResolutionInterceptor(ctx, aliasRepoFn),  // Resolve ids when an alias is provided
				subtypes.AttributeTransformerInterceptor(ctx), // convert to/from generic attributes from/to subtype specific attributes
				eventsRequestInterceptor(ctx),                 // before we get started, send the required events with the request
				statusCodeInterceptor(ctx),                    // convert grpc codes into http status codes for the http proxy (can modify the resp)
				eventsResponseInterceptor(ctx),                // as we finish, send the required events with the response
				grpc_recovery.UnaryServerInterceptor( // recover from panics with a grpc internal error
					grpc_recovery.WithRecoveryHandlerContext(recoveryHandler()),
				),
			),
		),
	), ticket, nil
}
