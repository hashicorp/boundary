package targets

import (
	"context"
	stderrors "errors"
	"fmt"
	"math/rand"
	"net/url"
	"strings"

	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/targets"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/host"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/servers"
	"github.com/hashicorp/boundary/internal/servers/controller/common"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/store"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/boundary/sdk/strutil"
	"github.com/mr-tron/base58"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	maskManager handlers.MaskManager
)

func init() {
	var err error
	if maskManager, err = handlers.NewMaskManager(&store.TcpTarget{}, &pb.Target{}, &pb.TcpTargetAttributes{}); err != nil {
		panic(err)
	}
}

// Service handles request as described by the pbs.TargetServiceServer interface.
type Service struct {
	pbs.UnimplementedTargetServiceServer

	repoFn           common.TargetRepoFactory
	iamRepoFn        common.IamRepoFactory
	serversRepoFn    common.ServersRepoFactory
	sessionRepoFn    common.SessionRepoFactory
	staticHostRepoFn common.StaticRepoFactory
	kmsCache         *kms.Kms
}

// NewService returns a target service which handles target related requests to boundary.
func NewService(
	kmsCache *kms.Kms,
	repoFn common.TargetRepoFactory,
	iamRepoFn common.IamRepoFactory,
	serversRepoFn common.ServersRepoFactory,
	sessionRepoFn common.SessionRepoFactory,
	staticHostRepoFn common.StaticRepoFactory) (Service, error) {
	if repoFn == nil {
		return Service{}, fmt.Errorf("nil target repository provided")
	}
	if iamRepoFn == nil {
		return Service{}, fmt.Errorf("nil iam repository provided")
	}
	if serversRepoFn == nil {
		return Service{}, fmt.Errorf("nil servers repository provided")
	}
	if sessionRepoFn == nil {
		return Service{}, fmt.Errorf("nil session repository provided")
	}
	if staticHostRepoFn == nil {
		return Service{}, fmt.Errorf("nil static host repository provided")
	}
	return Service{
		repoFn:           repoFn,
		iamRepoFn:        iamRepoFn,
		serversRepoFn:    serversRepoFn,
		sessionRepoFn:    sessionRepoFn,
		staticHostRepoFn: staticHostRepoFn,
		kmsCache:         kmsCache,
	}, nil
}

var _ pbs.TargetServiceServer = Service{}

// ListTargets implements the interface pbs.TargetServiceServer.
func (s Service) ListTargets(ctx context.Context, req *pbs.ListTargetsRequest) (*pbs.ListTargetsResponse, error) {
	if err := validateListRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetScopeId(), action.List)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	ul, err := s.listFromRepo(ctx, authResults.Scope.GetId())
	if err != nil {
		return nil, err
	}
	for _, item := range ul {
		item.Scope = authResults.Scope
	}
	return &pbs.ListTargetsResponse{Items: ul}, nil
}

// GetTargets implements the interface pbs.TargetServiceServer.
func (s Service) GetTarget(ctx context.Context, req *pbs.GetTargetRequest) (*pbs.GetTargetResponse, error) {
	if err := validateGetRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.Read)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	u, err := s.getFromRepo(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	u.Scope = authResults.Scope
	return &pbs.GetTargetResponse{Item: u}, nil
}

// CreateTarget implements the interface pbs.TargetServiceServer.
func (s Service) CreateTarget(ctx context.Context, req *pbs.CreateTargetRequest) (*pbs.CreateTargetResponse, error) {
	if err := validateCreateRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetItem().GetScopeId(), action.Create)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	u, err := s.createInRepo(ctx, req.GetItem())
	if err != nil {
		return nil, err
	}
	u.Scope = authResults.Scope
	return &pbs.CreateTargetResponse{Item: u, Uri: fmt.Sprintf("targets/%s", u.GetId())}, nil
}

// UpdateTarget implements the interface pbs.TargetServiceServer.
func (s Service) UpdateTarget(ctx context.Context, req *pbs.UpdateTargetRequest) (*pbs.UpdateTargetResponse, error) {
	if err := validateUpdateRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.Update)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	u, err := s.updateInRepo(ctx, authResults.Scope.GetId(), req.GetId(), req.GetUpdateMask().GetPaths(), req.GetItem())
	if err != nil {
		return nil, err
	}
	u.Scope = authResults.Scope
	return &pbs.UpdateTargetResponse{Item: u}, nil
}

// DeleteTarget implements the interface pbs.TargetServiceServer.
func (s Service) DeleteTarget(ctx context.Context, req *pbs.DeleteTargetRequest) (*pbs.DeleteTargetResponse, error) {
	if err := validateDeleteRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.Delete)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	_, err := s.deleteFromRepo(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	return &pbs.DeleteTargetResponse{}, nil
}

// AddTargetHostSets implements the interface pbs.TargetServiceServer.
func (s Service) AddTargetHostSets(ctx context.Context, req *pbs.AddTargetHostSetsRequest) (*pbs.AddTargetHostSetsResponse, error) {
	if err := validateAddRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.AddHostSets)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	u, err := s.addInRepo(ctx, req.GetId(), req.GetHostSetIds(), req.GetVersion())
	if err != nil {
		return nil, err
	}
	u.Scope = authResults.Scope
	return &pbs.AddTargetHostSetsResponse{Item: u}, nil
}

// SetTargetHostSets implements the interface pbs.TargetServiceServer.
func (s Service) SetTargetHostSets(ctx context.Context, req *pbs.SetTargetHostSetsRequest) (*pbs.SetTargetHostSetsResponse, error) {
	if err := validateSetRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.SetHostSets)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	u, err := s.setInRepo(ctx, req.GetId(), req.GetHostSetIds(), req.GetVersion())
	if err != nil {
		return nil, err
	}
	u.Scope = authResults.Scope
	return &pbs.SetTargetHostSetsResponse{Item: u}, nil
}

// RemoveTargetHostSets implements the interface pbs.TargetServiceServer.
func (s Service) RemoveTargetHostSets(ctx context.Context, req *pbs.RemoveTargetHostSetsRequest) (*pbs.RemoveTargetHostSetsResponse, error) {
	if err := validateRemoveRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.RemoveHostSets)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	u, err := s.removeInRepo(ctx, req.GetId(), req.GetHostSetIds(), req.GetVersion())
	if err != nil {
		return nil, err
	}
	u.Scope = authResults.Scope
	return &pbs.RemoveTargetHostSetsResponse{Item: u}, nil
}

func (s Service) AuthorizeSession(ctx context.Context, req *pbs.AuthorizeSessionRequest) (*pbs.AuthorizeSessionResponse, error) {
	if err := validateAuthorizeSessionRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.AuthorizeSession,
		target.WithName(req.GetName()),
		target.WithScopeId(req.GetScopeId()),
		target.WithScopeName(req.GetScopeName()),
	)
	if authResults.Error != nil {
		return nil, authResults.Error
	}

	if authResults.RoundTripValue == nil {
		return nil, stderrors.New("authorize session: expected to get a target back from auth results")
	}
	t, ok := authResults.RoundTripValue.(target.Target)
	if !ok {
		return nil, stderrors.New("authorize session: round tripped auth results value is not a target")
	}
	if t == nil {
		return nil, stderrors.New("authorize session: round tripped target is nil")
	}

	// This could happen if, say, u_recovery was used or u_anon was granted. But
	// don't allow it. It's one thing if grants give access to resources within
	// Boundary, even if those could eventually be used to provide an unintended
	// user access to a remote system. It's quite another to enable anonymous
	// access directly to a remote system.
	//
	// Note that even if u_anon or u_auth are given grants we can still validate
	// a token! So this is just checking that a valid token was provided. The
	// actual reality of this works out to excluding:
	//
	// * True anonymous access (no token provided and u_anon)
	//
	// * u_recovery access (which is fine, recovery is meant for recovering
	// system state, no real reason to allow it to then connect to systems)
	if authResults.AuthTokenId == "" {
		return nil, handlers.ForbiddenError()
	}

	// Get the target information
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	t, hostSets, err := repo.LookupTarget(ctx, t.GetPublicId())
	if err != nil {
		if errors.Is(err, errors.ErrRecordNotFound) {
			return nil, handlers.NotFoundErrorf("Target %q not found.", t.GetPublicId())
		}
		return nil, err
	}
	if t == nil {
		return nil, handlers.NotFoundErrorf("Target %q not found.", t.GetPublicId())
	}

	// Instantiate some repos
	sessionRepo, err := s.sessionRepoFn()
	if err != nil {
		return nil, err
	}
	serversRepo, err := s.serversRepoFn()
	if err != nil {
		return nil, err
	}

	// First, fetch all available hosts. Unless one was chosen in the request,
	// we will pick one at random.
	type compoundHost struct {
		hostSetId string
		hostId    string
	}

	var chosenId *compoundHost
	requestedId := req.GetHostId()
	staticHostRepo, err := s.staticHostRepoFn()
	if err != nil {
		return nil, err
	}

	hostIds := make([]compoundHost, 0, len(hostSets)*10)

HostSetIterationLoop:
	for _, tSet := range hostSets {
		hsId := tSet.PublicId
		switch host.SubtypeFromId(hsId) {
		case host.StaticSubtype:
			_, hosts, err := staticHostRepo.LookupSet(ctx, hsId)
			if err != nil {
				return nil, err
			}
			for _, host := range hosts {
				compoundId := compoundHost{hostSetId: hsId, hostId: host.PublicId}
				hostIds = append(hostIds, compoundId)
				if host.PublicId == requestedId {
					chosenId = &compoundId
					break HostSetIterationLoop
				}
			}
		}
	}
	if requestedId != "" && chosenId == nil {
		// We didn't find it
		return nil, handlers.InvalidArgumentErrorf(
			"Errors in provided fields.",
			map[string]string{
				"host_id": "The requested host id is not available.",
			})
	}
	if chosenId == nil {
		if len(hostIds) == 0 {
			// No hosts were found, error
			return nil, handlers.NotFoundErrorf("No hosts found from available target host sets.")
		}
		chosenId = &hostIds[rand.Intn(len(hostIds))]
	}

	// Generate the endpoint URL
	endpointUrl := &url.URL{
		Scheme: t.GetType(),
	}
	defaultPort := t.GetDefaultPort()
	var endpointHost string
	switch host.SubtypeFromId(chosenId.hostId) {
	case host.StaticSubtype:
		h, err := staticHostRepo.LookupHost(ctx, chosenId.hostId)
		if err != nil {
			return nil, fmt.Errorf("error looking up host: %w", err)
		}
		endpointHost = h.Address
		if endpointHost == "" {
			return nil, stderrors.New("host had empty address")
		}
	}
	if defaultPort != 0 {
		endpointUrl.Host = fmt.Sprintf("%s:%d", endpointHost, defaultPort)
	} else {
		endpointUrl.Host = endpointHost
	}

	expTime := timestamppb.Now()
	expTime.Seconds += int64(t.GetSessionMaxSeconds())
	sessionComposition := session.ComposedOf{
		UserId:          authResults.UserId,
		HostId:          chosenId.hostId,
		TargetId:        t.GetPublicId(),
		HostSetId:       chosenId.hostSetId,
		AuthTokenId:     authResults.AuthTokenId,
		ScopeId:         authResults.Scope.Id,
		Endpoint:        endpointUrl.String(),
		ExpirationTime:  &timestamp.Timestamp{Timestamp: expTime},
		ConnectionLimit: t.GetSessionConnectionLimit(),
	}

	sess, err := session.New(sessionComposition)
	if err != nil {
		return nil, err
	}
	wrapper, err := s.kmsCache.GetWrapper(ctx, authResults.Scope.Id, kms.KeyPurposeSessions)
	if err != nil {
		return nil, err
	}
	sess, privKey, err := sessionRepo.CreateSession(ctx, wrapper, sess)
	if err != nil {
		return nil, err
	}

	var workers []*pb.WorkerInfo
	servers, err := serversRepo.ListServers(ctx, servers.ServerTypeWorker)
	if err != nil {
		return nil, err
	}
	for _, v := range servers {
		workers = append(workers, &pb.WorkerInfo{Address: v.Address})
	}

	sad := &pb.SessionAuthorizationData{
		SessionId:       sess.PublicId,
		TargetId:        t.GetPublicId(),
		Scope:           authResults.Scope,
		CreatedTime:     sess.CreateTime.GetTimestamp(),
		Type:            t.GetType(),
		Certificate:     sess.Certificate,
		PrivateKey:      privKey,
		HostId:          chosenId.hostId,
		Endpoint:        endpointUrl.String(),
		WorkerInfo:      workers,
		ConnectionLimit: t.GetSessionConnectionLimit(),
	}
	marshaledSad, err := proto.Marshal(sad)
	if err != nil {
		return nil, err
	}
	encodedMarshaledSad := base58.FastBase58Encoding(marshaledSad)

	ret := &pb.SessionAuthorization{
		SessionId:          sess.PublicId,
		TargetId:           t.GetPublicId(),
		Scope:              authResults.Scope,
		CreatedTime:        sess.CreateTime.GetTimestamp(),
		Type:               t.GetType(),
		AuthorizationToken: string(encodedMarshaledSad),
		UserId:             authResults.UserId,
		HostId:             chosenId.hostId,
		HostSetId:          chosenId.hostSetId,
		Endpoint:           endpointUrl.String(),
	}
	return &pbs.AuthorizeSessionResponse{Item: ret}, nil
}

func (s Service) getFromRepo(ctx context.Context, id string) (*pb.Target, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	u, m, err := repo.LookupTarget(ctx, id)
	if err != nil {
		if errors.Is(err, errors.ErrRecordNotFound) {
			return nil, handlers.NotFoundErrorf("Target %q doesn't exist.", id)
		}
		return nil, err
	}
	if u == nil {
		return nil, handlers.NotFoundErrorf("Target %q doesn't exist.", id)
	}
	return toProto(u, m)
}

func (s Service) createInRepo(ctx context.Context, item *pb.Target) (*pb.Target, error) {
	opts := []target.Option{target.WithName(item.GetName().GetValue())}
	if item.GetDescription() != nil {
		opts = append(opts, target.WithDescription(item.GetDescription().GetValue()))
	}
	if item.GetSessionMaxSeconds() != nil {
		opts = append(opts, target.WithSessionMaxSeconds(item.GetSessionMaxSeconds().GetValue()))
	}
	if item.GetSessionConnectionLimit() != nil {
		opts = append(opts, target.WithSessionConnectionLimit(item.GetSessionConnectionLimit().GetValue()))
	}
	tcpAttrs := &pb.TcpTargetAttributes{}
	if err := handlers.StructToProto(item.GetAttributes(), tcpAttrs); err != nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.InvalidArgument, "Provided attributes don't match expected format.")
	}
	if tcpAttrs.GetDefaultPort().GetValue() != 0 {
		opts = append(opts, target.WithDefaultPort(tcpAttrs.GetDefaultPort().GetValue()))
	}
	u, err := target.NewTcpTarget(item.GetScopeId(), opts...)
	if err != nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to build target for creation: %v.", err)
	}
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	out, m, err := repo.CreateTcpTarget(ctx, u)
	if err != nil {
		return nil, fmt.Errorf("unable to create target: %w", err)
	}
	if out == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to create target but no error returned from repository.")
	}
	return toProto(out, m)
}

func (s Service) updateInRepo(ctx context.Context, scopeId, id string, mask []string, item *pb.Target) (*pb.Target, error) {
	var opts []target.Option
	if desc := item.GetDescription(); desc != nil {
		opts = append(opts, target.WithDescription(desc.GetValue()))
	}
	if name := item.GetName(); name != nil {
		opts = append(opts, target.WithName(name.GetValue()))
	}
	if item.GetSessionMaxSeconds() != nil {
		opts = append(opts, target.WithSessionMaxSeconds(item.GetSessionMaxSeconds().GetValue()))
	}
	if item.GetSessionConnectionLimit() != nil {
		opts = append(opts, target.WithSessionConnectionLimit(item.GetSessionConnectionLimit().GetValue()))
	}
	tcpAttrs := &pb.TcpTargetAttributes{}
	if err := handlers.StructToProto(item.GetAttributes(), tcpAttrs); err != nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.InvalidArgument, "Provided attributes don't match expected format.")
	}
	if tcpAttrs.GetDefaultPort().GetValue() != 0 {
		opts = append(opts, target.WithDefaultPort(tcpAttrs.GetDefaultPort().GetValue()))
	}
	version := item.GetVersion()
	u, err := target.NewTcpTarget(scopeId, opts...)
	if err != nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to build target for update: %v.", err)
	}
	u.PublicId = id
	dbMask := maskManager.Translate(mask)
	if len(dbMask) == 0 {
		return nil, handlers.InvalidArgumentErrorf("No valid fields included in the update mask.", map[string]string{"update_mask": "No valid paths provided in the update mask."})
	}
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	out, m, rowsUpdated, err := repo.UpdateTcpTarget(ctx, u, version, dbMask)
	if err != nil {
		return nil, fmt.Errorf("unable to update target: %w", err)
	}
	if rowsUpdated == 0 {
		return nil, handlers.NotFoundErrorf("Target %q not found or incorrect version provided.", id)
	}
	return toProto(out, m)
}

func (s Service) deleteFromRepo(ctx context.Context, id string) (bool, error) {
	repo, err := s.repoFn()
	if err != nil {
		return false, err
	}
	rows, err := repo.DeleteTarget(ctx, id)
	if err != nil {
		if errors.Is(err, errors.ErrRecordNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("unable to delete target: %w", err)
	}
	return rows > 0, nil
}

func (s Service) listFromRepo(ctx context.Context, scopeId string) ([]*pb.Target, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	ul, err := repo.ListTargets(ctx, target.WithScopeId(scopeId))
	if err != nil {
		return nil, err
	}
	var outUl []*pb.Target
	for _, u := range ul {
		o, err := toProto(u, nil)
		if err != nil {
			return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to convert value to proto: %v.", err)
		}
		outUl = append(outUl, o)
	}
	return outUl, nil
}

func (s Service) addInRepo(ctx context.Context, targetId string, hostSetId []string, version uint32) (*pb.Target, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	out, m, err := repo.AddTargetHostSets(ctx, targetId, version, strutil.RemoveDuplicates(hostSetId, false))
	if err != nil {
		// TODO: Figure out a way to surface more helpful error info beyond the Internal error.
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to add host sets to target: %v.", err)
	}
	if out == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to lookup target after adding host sets to it.")
	}
	return toProto(out, m)
}

func (s Service) setInRepo(ctx context.Context, targetId string, hostSetIds []string, version uint32) (*pb.Target, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	_, _, err = repo.SetTargetHostSets(ctx, targetId, version, strutil.RemoveDuplicates(hostSetIds, false))
	if err != nil {
		// TODO: Figure out a way to surface more helpful error info beyond the Internal error.
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to set host sets in target: %v.", err)
	}

	out, m, err := repo.LookupTarget(ctx, targetId)
	if err != nil {
		return nil, fmt.Errorf("unable to look up target after setting host sets: %w", err)
	}
	if out == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to lookup target after setting host sets for it.")
	}
	return toProto(out, m)
}

func (s Service) removeInRepo(ctx context.Context, targetId string, hostSetIds []string, version uint32) (*pb.Target, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	_, err = repo.DeleteTargeHostSets(ctx, targetId, version, strutil.RemoveDuplicates(hostSetIds, false))
	if err != nil {
		// TODO: Figure out a way to surface more helpful error info beyond the Internal error.
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to remove host sets from target: %v.", err)
	}
	out, m, err := repo.LookupTarget(ctx, targetId)
	if err != nil {
		return nil, fmt.Errorf("unable to look up target after removing host sets: %w", err)
	}
	if out == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to lookup target after removing host sets from it.")
	}
	return toProto(out, m)
}

func (s Service) authResult(ctx context.Context, id string, a action.Type, lookupOpt ...target.Option) auth.VerifyResults {
	res := auth.VerifyResults{}

	var parentId string
	var t target.Target
	opts := []auth.Option{auth.WithType(resource.Target), auth.WithAction(a)}
	switch a {
	case action.List, action.Create:
		parentId = id
		iamRepo, err := s.iamRepoFn()
		if err != nil {
			res.Error = err
			return res
		}
		scp, err := iamRepo.LookupScope(ctx, parentId)
		if err != nil {
			res.Error = err
			return res
		}
		if scp == nil {
			res.Error = handlers.NotFoundError()
			return res
		}
	default:
		repo, err := s.repoFn()
		if err != nil {
			res.Error = err
			return res
		}
		t, _, err = repo.LookupTarget(ctx, id, lookupOpt...)
		if err != nil {
			// TODO: Fix this with new/better error handling
			if strings.Contains(err.Error(), "more than one row returned by a subquery") {
				res.Error = handlers.ApiErrorWithCodeAndMessage(codes.FailedPrecondition, "Scope name is ambiguous (matches more than one scope), use scope ID with target name instead, or use target ID.")
			} else {
				res.Error = err
			}
			return res
		}
		if t == nil {
			res.Error = handlers.NotFoundError()
			return res
		}
		id = t.GetPublicId()
		parentId = t.GetScopeId()
		opts = append(opts, auth.WithId(id))
	}
	opts = append(opts, auth.WithScopeId(parentId))
	ret := auth.Verify(ctx, opts...)
	ret.RoundTripValue = t
	return ret
}

func toProto(in target.Target, m []*target.TargetSet) (*pb.Target, error) {
	out := pb.Target{
		Id:                     in.GetPublicId(),
		ScopeId:                in.GetScopeId(),
		CreatedTime:            in.GetCreateTime().GetTimestamp(),
		UpdatedTime:            in.GetUpdateTime().GetTimestamp(),
		Version:                in.GetVersion(),
		Type:                   target.TcpTargetType.String(),
		SessionMaxSeconds:      wrapperspb.UInt32(in.GetSessionMaxSeconds()),
		SessionConnectionLimit: wrapperspb.Int32(in.GetSessionConnectionLimit()),
	}
	if in.GetDescription() != "" {
		out.Description = wrapperspb.String(in.GetDescription())
	}
	if in.GetName() != "" {
		out.Name = wrapperspb.String(in.GetName())
	}
	attrs := &pb.TcpTargetAttributes{}
	if in.GetDefaultPort() > 0 {
		attrs.DefaultPort = &wrappers.UInt32Value{Value: in.GetDefaultPort()}
	}
	st, err := handlers.ProtoToStruct(attrs)
	if err != nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "failed building password attribute struct: %v", err)
	}
	out.Attributes = st
	for _, hs := range m {
		out.HostSetIds = append(out.HostSetIds, hs.GetPublicId())
		out.HostSets = append(out.HostSets, &pb.HostSet{
			Id:            hs.GetPublicId(),
			HostCatalogId: hs.GetCatalogId(),
		})
	}
	return &out, nil
}

// A validateX method should exist for each method above.  These methods do not make calls to any backing service but enforce
// requirements on the structure of the request.  They verify that:
//  * The path passed in is correctly formatted
//  * All required parameters are set
//  * There are no conflicting parameters provided
func validateGetRequest(req *pbs.GetTargetRequest) error {
	return handlers.ValidateGetRequest(target.TcpTargetPrefix, req, handlers.NoopValidatorFn)
}

func validateCreateRequest(req *pbs.CreateTargetRequest) error {
	return handlers.ValidateCreateRequest(req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		if !handlers.ValidId(scope.Project.Prefix(), req.GetItem().GetScopeId()) {
			badFields["scope_id"] = "This field is required to have a properly formatted project scope id."
		}
		if req.GetItem().GetName() == nil || req.GetItem().GetName().GetValue() == "" {
			badFields["name"] = "This field is required."
		}
		if req.GetItem().GetSessionConnectionLimit() != nil {
			val := req.GetItem().GetSessionConnectionLimit().GetValue()
			switch {
			case val == -1:
			case val > 0:
			default:
				badFields["session_connection_limit"] = "This must be -1 (unlimited) or greater than zero."
			}
		}
		if req.GetItem().GetSessionMaxSeconds() != nil && req.GetItem().GetSessionMaxSeconds().GetValue() == 0 {
			badFields["session_max_seconds"] = "This must be greater than zero."
		}
		switch target.SubtypeFromType(req.GetItem().GetType()) {
		case target.TcpSubType:
			tcpAttrs := &pb.TcpTargetAttributes{}
			if err := handlers.StructToProto(req.GetItem().GetAttributes(), tcpAttrs); err != nil {
				badFields["attributes"] = "Attribute fields do not match the expected format."
			}
			if tcpAttrs.GetDefaultPort() != nil && tcpAttrs.GetDefaultPort().GetValue() == 0 {
				badFields["attributes.default_port"] = "This optional field cannot be set to 0."
			}
		}
		switch req.GetItem().GetType() {
		case target.TcpTargetType.String():
		case "":
			badFields["type"] = "This is a required field."
		default:
			badFields["type"] = "Unknown type provided."
		}
		return badFields
	})
}

func validateUpdateRequest(req *pbs.UpdateTargetRequest) error {
	return handlers.ValidateUpdateRequest(target.TcpTargetPrefix, req, req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		if handlers.MaskContains(req.GetUpdateMask().GetPaths(), "name") && req.GetItem().GetName().GetValue() == "" {
			badFields["name"] = "This field cannot be set to empty."
		}
		if req.GetItem().GetSessionConnectionLimit() != nil {
			val := req.GetItem().GetSessionConnectionLimit().GetValue()
			switch {
			case val == -1:
			case val > 0:
			default:
				badFields["session_connection_limit"] = "This must be -1 (unlimited) or greater than zero."
			}
		}
		if req.GetItem().GetSessionMaxSeconds() != nil && req.GetItem().GetSessionMaxSeconds().GetValue() == 0 {
			badFields["session_max_seconds"] = "This must be greater than zero."
		}
		switch target.SubtypeFromId(req.GetItem().GetType()) {
		case target.TcpSubType:
			if req.GetItem().GetType() != "" && target.SubtypeFromType(req.GetItem().GetType()) != target.TcpSubType {
				badFields["type"] = "Cannot modify the resource type."
			}
			tcpAttrs := &pb.TcpTargetAttributes{}
			if err := handlers.StructToProto(req.GetItem().GetAttributes(), tcpAttrs); err != nil {
				badFields["attributes"] = "Attribute fields do not match the expected format."
			}
			if tcpAttrs.GetDefaultPort() != nil && tcpAttrs.GetDefaultPort().GetValue() == 0 {
				badFields["attributes.default_port"] = "This optional field cannot be set to 0."
			}
		}
		return badFields
	})
}

func validateDeleteRequest(req *pbs.DeleteTargetRequest) error {
	return handlers.ValidateDeleteRequest(target.TcpTargetPrefix, req, handlers.NoopValidatorFn)
}

func validateListRequest(req *pbs.ListTargetsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(scope.Project.Prefix(), req.GetScopeId()) {
		badFields["scope_id"] = "This field is required to have a properly formatted project scope id."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Improperly formatted identifier.", badFields)
	}
	return nil
}

func validateAddRequest(req *pbs.AddTargetHostSetsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(target.TcpTargetPrefix, req.GetId()) {
		badFields["id"] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields["version"] = "Required field."
	}
	if len(req.GetHostSetIds()) == 0 {
		badFields["host_set_ids"] = "Must be non-empty."
	}
	for _, id := range req.GetHostSetIds() {
		if !handlers.ValidId(static.HostSetPrefix, id) {
			badFields["host_set_ids"] = fmt.Sprintf("Incorrectly formatted host set identifier %q.", id)
			break
		}
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}

func validateSetRequest(req *pbs.SetTargetHostSetsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(target.TcpTargetPrefix, req.GetId()) {
		badFields["id"] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields["version"] = "Required field."
	}
	for _, id := range req.GetHostSetIds() {
		if !handlers.ValidId(static.HostSetPrefix, id) {
			badFields["host_set_ids"] = fmt.Sprintf("Incorrectly formatted host set identifier %q.", id)
			break
		}
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}

func validateRemoveRequest(req *pbs.RemoveTargetHostSetsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(target.TcpTargetPrefix, req.GetId()) {
		badFields["id"] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields["version"] = "Required field."
	}
	if len(req.GetHostSetIds()) == 0 {
		badFields["host_set_ids"] = "Must be non-empty."
	}
	for _, id := range req.GetHostSetIds() {
		if !handlers.ValidId(static.HostSetPrefix, id) {
			badFields["host_set_ids"] = fmt.Sprintf("Incorrectly formatted host set identifier %q.", id)
			break
		}
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}

func validateAuthorizeSessionRequest(req *pbs.AuthorizeSessionRequest) error {
	badFields := map[string]string{}
	nameEmpty := req.GetName() == ""
	scopeIdEmpty := req.GetScopeId() == ""
	scopeNameEmpty := req.GetScopeName() == ""
	if nameEmpty {
		if !handlers.ValidId(target.TcpTargetPrefix, req.GetId()) {
			badFields["id"] = "Incorrectly formatted identifier."
		}
		if !scopeIdEmpty {
			badFields["scope_id"] = "Scope ID provided when target name was empty."
		}
		if !scopeNameEmpty {
			badFields["scope_id"] = "Scope name provided when target name was empty."
		}
	} else {
		if req.GetName() != req.GetId() {
			badFields["name"] = "Target name provided but does not match the given ID value from the URL."
		}
		switch {
		case scopeIdEmpty && scopeNameEmpty:
			badFields["scope_id"] = "Scope ID or scope name must be provided when target name is used."
			badFields["scope_name"] = "Scope ID or scope name must be provided when target name is used."
		case !scopeIdEmpty && !scopeNameEmpty:
			badFields["scope_id"] = "Scope ID and scope name cannot both be provided when target name is used."
			badFields["scope_name"] = "Scope ID and scope name cannot both be provided when target name is used."
		}
	}
	if req.GetHostId() != "" {
		switch host.SubtypeFromId(req.GetHostId()) {
		case host.StaticSubtype:
		default:
			badFields["host_id"] = "Incorrectly formatted identifier."
		}
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}
