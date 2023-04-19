// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package loopback

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"sync"
	"time"

	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var _ plgpb.StoragePluginServiceServer = (*TestPluginStorageServer)(nil)

// TestPluginStorageServer provides a storage plugin service server where each method can be overwritten for tests.
type TestPluginStorageServer struct {
	OnCreateStorageBucketFn func(context.Context, *plgpb.OnCreateStorageBucketRequest) (*plgpb.OnCreateStorageBucketResponse, error)
	OnUpdateStorageBucketFn func(context.Context, *plgpb.OnUpdateStorageBucketRequest) (*plgpb.OnUpdateStorageBucketResponse, error)
	OnDeleteStorageBucketFn func(context.Context, *plgpb.OnDeleteStorageBucketRequest) (*plgpb.OnDeleteStorageBucketResponse, error)
	ValidatePermissionsFn   func(context.Context, *plgpb.ValidatePermissionsRequest) (*plgpb.ValidatePermissionsResponse, error)
	HeadObjectFn            func(context.Context, *plgpb.HeadObjectRequest) (*plgpb.HeadObjectResponse, error)
	GetObjectFn             func(*plgpb.GetObjectRequest, plgpb.StoragePluginService_GetObjectServer) error
	PutObjectFn             func(plgpb.StoragePluginService_PutObjectServer) error
	plgpb.UnimplementedStoragePluginServiceServer
}

func (t TestPluginStorageServer) OnCreateStorageBucket(ctx context.Context, req *plgpb.OnCreateStorageBucketRequest) (*plgpb.OnCreateStorageBucketResponse, error) {
	if t.OnCreateStorageBucketFn == nil {
		return t.UnimplementedStoragePluginServiceServer.OnCreateStorageBucket(ctx, req)
	}
	return t.OnCreateStorageBucketFn(ctx, req)
}

func (t TestPluginStorageServer) OnUpdateStorageBucket(ctx context.Context, req *plgpb.OnUpdateStorageBucketRequest) (*plgpb.OnUpdateStorageBucketResponse, error) {
	if t.OnUpdateStorageBucketFn == nil {
		return t.UnimplementedStoragePluginServiceServer.OnUpdateStorageBucket(ctx, req)
	}
	return t.OnUpdateStorageBucketFn(ctx, req)
}

func (t TestPluginStorageServer) OnDeleteStorageBucket(ctx context.Context, req *plgpb.OnDeleteStorageBucketRequest) (*plgpb.OnDeleteStorageBucketResponse, error) {
	if t.OnDeleteStorageBucketFn == nil {
		return t.UnimplementedStoragePluginServiceServer.OnDeleteStorageBucket(ctx, req)
	}
	return t.OnDeleteStorageBucketFn(ctx, req)
}

func (t TestPluginStorageServer) ValidatePermissions(ctx context.Context, req *plgpb.ValidatePermissionsRequest) (*plgpb.ValidatePermissionsResponse, error) {
	if t.ValidatePermissionsFn == nil {
		return t.UnimplementedStoragePluginServiceServer.ValidatePermissions(ctx, req)
	}
	return t.ValidatePermissionsFn(ctx, req)
}

func (t TestPluginStorageServer) HeadObject(ctx context.Context, req *plgpb.HeadObjectRequest) (*plgpb.HeadObjectResponse, error) {
	if t.HeadObjectFn == nil {
		return t.UnimplementedStoragePluginServiceServer.HeadObject(ctx, req)
	}
	return t.HeadObjectFn(ctx, req)
}

func (t TestPluginStorageServer) GetObject(req *plgpb.GetObjectRequest, stream plgpb.StoragePluginService_GetObjectServer) error {
	if t.GetObjectFn == nil {
		return t.UnimplementedStoragePluginServiceServer.GetObject(req, stream)
	}
	return t.GetObjectFn(req, stream)
}

func (t TestPluginStorageServer) PutObject(stream plgpb.StoragePluginService_PutObjectServer) error {
	if t.PutObjectFn == nil {
		return t.UnimplementedStoragePluginServiceServer.PutObject(stream)
	}
	return t.PutObjectFn(stream)
}

type (
	BucketName string
	ObjectName string
	Chunk      []byte
)

type Bucket map[ObjectName]*storagePluginStorageInfo

// storagePluginStorageInfo is an in-memory represenation of an object
// that would be normally stored in an external object store.
type storagePluginStorageInfo struct {
	DataChunks []Chunk `mapstructure:"dataChunks"`

	lastModified  *time.Time `mapstructure:"lastModified"`
	contentLength *int64     `mapstructure:"contentLength"`
}

// LoopbackStorage provides a storage plugin with functionality useful for certain
// kinds of testing.
//
// It is thread-safe.
type LoopbackStorage struct {
	m sync.Mutex

	buckets map[BucketName]Bucket
	errs    []PluginMockError
}

func (l *LoopbackStorage) onCreateStorageBucket(ctx context.Context, req *plgpb.OnCreateStorageBucketRequest) (*plgpb.OnCreateStorageBucketResponse, error) {
	const op = "loopback.(LoopbackPlugin).onCreateStorageBucket"
	if req == nil {
		return nil, status.Errorf(codes.InvalidArgument, "%s: request is nil", op)
	}
	if req.Bucket == nil {
		return nil, status.Errorf(codes.InvalidArgument, "%s: missing storage bucket", op)
	}
	if req.GetBucket().Secrets == nil {
		return nil, status.Errorf(codes.InvalidArgument, "%s: missing secrets", op)
	}
	l.m.Lock()
	defer l.m.Unlock()
	if _, ok := l.buckets[BucketName(req.GetBucket().GetBucketName())]; !ok {
		return nil, status.Errorf(codes.NotFound, "%s: bucket not found", op)
	}
	for _, err := range l.errs {
		if err.match(req.GetBucket(), "") {
			return nil, status.Errorf(err.errCode, err.errMsg)
		}
	}
	return &plgpb.OnCreateStorageBucketResponse{
		Persisted: &plgpb.StorageBucketPersisted{
			Data: req.GetBucket().GetSecrets(),
		},
	}, nil
}

func (l *LoopbackStorage) onUpdateStorageBucket(ctx context.Context, req *plgpb.OnUpdateStorageBucketRequest) (*plgpb.OnUpdateStorageBucketResponse, error) {
	const op = "loopback.(LoopbackPlugin).onUpdateStorageBucket"
	if req == nil {
		return nil, status.Errorf(codes.InvalidArgument, "%s: request is nil", op)
	}
	if req.NewBucket == nil {
		return nil, status.Errorf(codes.InvalidArgument, "%s: missing storage bucket", op)
	}
	if req.GetNewBucket().Secrets == nil {
		return nil, status.Errorf(codes.InvalidArgument, "%s: missing secrets", op)
	}
	l.m.Lock()
	defer l.m.Unlock()
	if _, ok := l.buckets[BucketName(req.GetNewBucket().GetBucketName())]; !ok {
		return nil, status.Errorf(codes.NotFound, "%s: bucket not found", op)
	}
	for _, err := range l.errs {
		if err.match(req.GetNewBucket(), "") {
			return nil, status.Errorf(err.errCode, "%s: %s", op, err.errMsg)
		}
	}
	return &plgpb.OnUpdateStorageBucketResponse{
		Persisted: &plgpb.StorageBucketPersisted{
			Data: req.GetNewBucket().GetSecrets(),
		},
	}, nil
}

func (l *LoopbackStorage) onDeleteStorageBucket(ctx context.Context, req *plgpb.OnDeleteStorageBucketRequest) (*plgpb.OnDeleteStorageBucketResponse, error) {
	const op = "loopback.(LoopbackPlugin).onDeleteStorageBucket"
	if req == nil {
		return nil, status.Errorf(codes.InvalidArgument, "%s: request is nil", op)
	}
	if req.Bucket == nil {
		return nil, status.Errorf(codes.InvalidArgument, "%s: missing storage bucket", op)
	}
	if req.GetBucket().Secrets == nil {
		return nil, status.Errorf(codes.InvalidArgument, "%s: missing secrets", op)
	}
	return &plgpb.OnDeleteStorageBucketResponse{}, nil
}

func (l *LoopbackStorage) validatePermissions(ctx context.Context, req *plgpb.ValidatePermissionsRequest) (*plgpb.ValidatePermissionsResponse, error) {
	const op = "loopback.(LoopbackPlugin).validatePermissions"
	if req == nil {
		return nil, status.Errorf(codes.InvalidArgument, "%s: request is nil", op)
	}
	if req.Bucket == nil {
		return nil, status.Errorf(codes.InvalidArgument, "%s: missing storage bucket", op)
	}
	if req.GetBucket().Secrets == nil {
		return nil, status.Errorf(codes.InvalidArgument, "%s: missing secrets", op)
	}
	l.m.Lock()
	defer l.m.Unlock()
	if _, ok := l.buckets[BucketName(req.GetBucket().GetBucketName())]; !ok {
		return nil, status.Errorf(codes.NotFound, "%s: bucket not found", op)
	}
	for _, err := range l.errs {
		if err.match(req.GetBucket(), "") {
			return nil, status.Errorf(err.errCode, "%s: %s", op, err.errMsg)
		}
	}
	return &plgpb.ValidatePermissionsResponse{}, nil
}

func (l *LoopbackStorage) headObject(ctx context.Context, req *plgpb.HeadObjectRequest) (*plgpb.HeadObjectResponse, error) {
	const op = "loopback.(LoopbackPlugin).headObject"
	if req == nil {
		return nil, status.Errorf(codes.InvalidArgument, "%s: request is nil", op)
	}
	if req.Bucket == nil {
		return nil, status.Errorf(codes.InvalidArgument, "$%s: missing storage bucket", op)
	}
	if req.GetBucket().Secrets == nil {
		return nil, status.Errorf(codes.InvalidArgument, "%s: missing secrets", op)
	}
	if req.Key == "" {
		return nil, status.Errorf(codes.InvalidArgument, "%s; missing object key", op)
	}
	l.m.Lock()
	defer l.m.Unlock()
	bucket, ok := l.buckets[BucketName(req.GetBucket().GetBucketName())]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "%s: bucket not found", op)
	}
	objectPath := ObjectName(req.GetBucket().GetBucketPrefix() + req.GetKey())
	object, ok := bucket[objectPath]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "%s: object %s not found", op, objectPath)
	}
	for _, err := range l.errs {
		if err.match(req.GetBucket(), req.GetKey()) {
			return nil, status.Errorf(err.errCode, "%s: %s", op, err.errMsg)
		}
	}
	return &plgpb.HeadObjectResponse{
		ContentLength: *object.contentLength,
		LastModified:  timestamppb.New(*object.lastModified),
	}, nil
}

func (l *LoopbackStorage) getObject(req *plgpb.GetObjectRequest, stream plgpb.StoragePluginService_GetObjectServer) error {
	const op = "loopback.(LoopbackPlugin).getObject"
	if req == nil {
		return status.Errorf(codes.InvalidArgument, "%s: request is nil", op)
	}
	if req.Bucket == nil {
		return status.Errorf(codes.InvalidArgument, "%s: missing storage bucket", op)
	}
	if req.GetBucket().Secrets == nil {
		return status.Errorf(codes.InvalidArgument, "%s: missing secrets", op)
	}
	if req.Key == "" {
		return status.Errorf(codes.InvalidArgument, "%s; missing object key", op)
	}
	l.m.Lock()
	defer l.m.Unlock()
	bucket, ok := l.buckets[BucketName(req.GetBucket().GetBucketName())]
	if !ok {
		return status.Errorf(codes.NotFound, "%s: bucket not found", op)
	}
	objectPath := ObjectName(req.GetBucket().GetBucketPrefix() + req.GetKey())
	object, ok := bucket[objectPath]
	if !ok {
		return status.Errorf(codes.NotFound, "%s: object %s not found", op, objectPath)
	}
	for _, err := range l.errs {
		if err.match(req.GetBucket(), req.GetKey()) {
			return status.Errorf(err.errCode, "%s: %s", op, err.errMsg)
		}
	}
	go func() {
		for _, chunk := range object.DataChunks {
			if err := stream.Send(&plgpb.GetObjectResponse{
				FileChunk: chunk,
			}); err != nil {
				stream.SendMsg(status.Errorf(codes.Internal, "%s: failed to send object data: %v", op, err))
				return
			}
		}
		stream.SendMsg(io.EOF)
	}()
	return nil
}

func (l *LoopbackStorage) putObject(stream plgpb.StoragePluginService_PutObjectServer) error {
	const op = "loopback.(LoopbackPlugin).putObject"
	if stream == nil {
		return status.Errorf(codes.Internal, "%s: missing stream", op)
	}
	go func() {
		var (
			request      *plgpb.PutObjectRequest_Request
			objectChunks []Chunk
			objectData   []byte
		)
		for {
			req, err := stream.Recv()
			if err == io.EOF {
				break
			}
			if err != nil {
				_ = stream.SendMsg(status.Errorf(codes.Internal, "%s: failed to recv message from stream: %v", op, err))
				return
			}
			switch data := req.Data.(type) {
			case *plgpb.PutObjectRequest_Request:
				if data.Request == nil {
					_ = stream.SendMsg(status.Errorf(codes.InvalidArgument, "%s: missing request metadata", op))
					return
				}
				if data.Request.GetBucket() == nil {
					_ = stream.SendMsg(status.Errorf(codes.InvalidArgument, "%s: missing storage bucket", op))
					return
				}
				if data.Request.GetBucket().GetSecrets() == nil {
					_ = stream.SendMsg(status.Errorf(codes.InvalidArgument, "%s: missing secrets", op))
					return
				}
				if data.Request.Key == "" {
					_ = stream.SendMsg(status.Errorf(codes.InvalidArgument, "%s; missing object key", op))
					return
				}
				request = data
			case *plgpb.PutObjectRequest_FileChunk:
				objectChunks = append(objectChunks, data.FileChunk)
				objectData = append(objectData, data.FileChunk...)
			case nil:
				continue
			default:
				_ = stream.SendMsg(status.Errorf(codes.Internal, "%s: unknown message type: %v", op, data))
				return
			}
		}
		if request == nil {
			_ = stream.SendMsg(status.Errorf(codes.InvalidArgument, "%s: request is nil", op))
			return
		}
		if len(objectData) <= 0 {
			_ = stream.SendMsg(status.Errorf(codes.InvalidArgument, "%s: missing object data", op))
			return
		}
		l.m.Lock()
		defer l.m.Unlock()
		bucket, ok := l.buckets[BucketName(request.Request.GetBucket().GetBucketName())]
		if !ok {
			_ = stream.SendMsg(status.Errorf(codes.NotFound, "%s: bucket not found", op))
			return
		}
		for _, err := range l.errs {
			if err.match(request.Request.GetBucket(), request.Request.GetKey()) {
				_ = stream.SendMsg(status.Errorf(err.errCode, "%s: %s", op, err.errMsg))
				return
			}
		}
		hash := sha256.New()
		if _, err := io.Copy(hash, bytes.NewReader(objectData)); err != nil {
			_ = stream.SendMsg(status.Errorf(codes.Internal, "%s: failed to hash object: %v", op, err))
			return
		}
		contentLength := int64(len(objectData))
		lastModified := time.Now()
		objectPath := ObjectName(request.Request.GetBucket().GetBucketPrefix() + request.Request.GetKey())
		bucket[objectPath] = &storagePluginStorageInfo{
			DataChunks:    objectChunks,
			contentLength: &contentLength,
			lastModified:  &lastModified,
		}
		if err := stream.SendAndClose(&plgpb.PutObjectResponse{
			ChecksumSha_256: hash.Sum(nil),
		}); err != nil {
			_ = stream.SendMsg(status.Errorf(codes.Internal, "%s: failed to close stream: %v", op, err))
			return
		}
	}()
	return nil
}

func MockObject(data []Chunk) *storagePluginStorageInfo {
	lastModified := time.Now()
	dataChunks := make([]Chunk, len(data))
	var contentLength int64
	for i, chunk := range data {
		dataChunks[i] = copyBytes(chunk)
		contentLength += int64(len(chunk))
	}
	return &storagePluginStorageInfo{
		DataChunks:    dataChunks,
		contentLength: &contentLength,
		lastModified:  &lastModified,
	}
}

func copyBytes(in []byte) []byte {
	return append([]byte{}, in...)
}
