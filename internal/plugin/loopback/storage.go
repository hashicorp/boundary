// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package loopback

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/storagebuckets"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var _ plgpb.StoragePluginServiceServer = (*TestPluginStorageServer)(nil)

// TestPluginStorageServer provides a storage plugin service server where each method can be overwritten for tests.
type TestPluginStorageServer struct {
	NormalizeStorageBucketDataFn func(context.Context, *plgpb.NormalizeStorageBucketDataRequest) (*plgpb.NormalizeStorageBucketDataResponse, error)
	OnCreateStorageBucketFn      func(context.Context, *plgpb.OnCreateStorageBucketRequest) (*plgpb.OnCreateStorageBucketResponse, error)
	OnUpdateStorageBucketFn      func(context.Context, *plgpb.OnUpdateStorageBucketRequest) (*plgpb.OnUpdateStorageBucketResponse, error)
	OnDeleteStorageBucketFn      func(context.Context, *plgpb.OnDeleteStorageBucketRequest) (*plgpb.OnDeleteStorageBucketResponse, error)
	ValidatePermissionsFn        func(context.Context, *plgpb.ValidatePermissionsRequest) (*plgpb.ValidatePermissionsResponse, error)
	HeadObjectFn                 func(context.Context, *plgpb.HeadObjectRequest) (*plgpb.HeadObjectResponse, error)
	GetObjectFn                  func(*plgpb.GetObjectRequest, plgpb.StoragePluginService_GetObjectServer) error
	PutObjectFn                  func(context.Context, *plgpb.PutObjectRequest) (*plgpb.PutObjectResponse, error)
	DeleteObjectsFn              func(context.Context, *plgpb.DeleteObjectsRequest) (*plgpb.DeleteObjectsResponse, error)
	plgpb.UnimplementedStoragePluginServiceServer
}

func (t TestPluginStorageServer) NormalizeStorageBucketData(ctx context.Context, req *plgpb.NormalizeStorageBucketDataRequest) (*plgpb.NormalizeStorageBucketDataResponse, error) {
	if t.NormalizeStorageBucketDataFn == nil {
		return t.UnimplementedStoragePluginServiceServer.NormalizeStorageBucketData(ctx, req)
	}
	return t.NormalizeStorageBucketDataFn(ctx, req)
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

func (t TestPluginStorageServer) PutObject(ctx context.Context, req *plgpb.PutObjectRequest) (*plgpb.PutObjectResponse, error) {
	if t.PutObjectFn == nil {
		return t.UnimplementedStoragePluginServiceServer.PutObject(ctx, req)
	}
	return t.PutObjectFn(ctx, req)
}

func (t TestPluginStorageServer) DeleteObjects(ctx context.Context, req *plgpb.DeleteObjectsRequest) (*plgpb.DeleteObjectsResponse, error) {
	if t.DeleteObjectsFn == nil {
		return t.UnimplementedStoragePluginServiceServer.DeleteObjects(ctx, req)
	}
	return t.DeleteObjectsFn(ctx, req)
}

type (
	BucketName string
	ObjectName string
	Chunk      []byte
)

type Bucket map[ObjectName]*storagePluginStorageInfo

// storagePluginStorageInfo is an in-memory representation of an object
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

	chunksSize        int
	buckets           map[BucketName]Bucket
	errs              []PluginMockError
	putObjectResponse []PluginMockPutObjectResponse
	normalizations    int
}

func (l *LoopbackStorage) normalizeStorageBucketData(ctx context.Context, req *plgpb.NormalizeStorageBucketDataRequest) (*plgpb.NormalizeStorageBucketDataResponse, error) {
	const op = "loopback.(LoopbackStorage).normalizeStorageBucketData"
	if req == nil {
		return nil, status.Errorf(codes.InvalidArgument, "%s: request is nil", op)
	}
	if req.GetAttributes() == nil {
		return nil, status.Errorf(codes.InvalidArgument, "%s: missing attributes", op)
	}
	attrs := req.GetAttributes()
	if endpoint, ok := attrs.GetFields()["endpoint_url"]; ok {
		if endpoint, err := parseutil.NormalizeAddr(endpoint.GetStringValue()); err == nil {
			attrs.Fields["endpoint_url"] = structpb.NewStringValue(endpoint)
		}
	}
	l.normalizations++
	return &plgpb.NormalizeStorageBucketDataResponse{
		Attributes: attrs,
	}, nil
}

// ResetNormalizations sets the number of times that NormalizeStorageBucketData
// has been called to 0. Useful for unit tests.
func (l *LoopbackStorage) ResetNormalizations() {
	l.normalizations = 0
}

// GetNormalizations returns the number of times that NormalizeStorageBucketData
// has been called via the loopback plugin. Useful for unit tests.
func (l *LoopbackStorage) GetNormalizations() int {
	return l.normalizations
}

func (l *LoopbackStorage) onCreateStorageBucket(ctx context.Context, req *plgpb.OnCreateStorageBucketRequest) (*plgpb.OnCreateStorageBucketResponse, error) {
	const op = "loopback.(LoopbackStorage).onCreateStorageBucket"
	if req == nil {
		return nil, status.Errorf(codes.InvalidArgument, "%s: request is nil", op)
	}
	if req.GetBucket() == nil {
		return nil, status.Errorf(codes.InvalidArgument, "%s: missing storage bucket", op)
	}
	if req.GetBucket().GetAttributes() == nil {
		return nil, status.Errorf(codes.InvalidArgument, "%s: missing attributes", op)
	}
	l.m.Lock()
	defer l.m.Unlock()
	if _, ok := l.buckets[BucketName(req.GetBucket().GetBucketName())]; !ok {
		return nil, status.Errorf(codes.NotFound, "%s: bucket not found", op)
	}
	for _, err := range l.errs {
		if err.match(req.GetBucket(), "", OnCreateStorageBucket) {
			return nil, status.Error(err.ErrCode, err.ErrMsg)
		}
	}
	secrets := &structpb.Struct{
		Fields: make(map[string]*structpb.Value),
	}
	var hasDynamicCreds bool
	attrs := req.GetBucket().GetAttributes()
	if attrs != nil {
		_, hasDynamicCreds = attrs.Fields[ConstDynamicCredentials]
	}
	var hasStaticCreds bool
	if req.GetBucket().GetSecrets() != nil && len(req.GetBucket().GetSecrets().AsMap()) > 0 {
		hasStaticCreds = true
		secrets = req.GetBucket().GetSecrets()
	}
	if hasDynamicCreds && hasStaticCreds {
		return nil, status.Errorf(codes.InvalidArgument, "%s: cannot use both dynamic and static credentials", op)
	}
	return &plgpb.OnCreateStorageBucketResponse{
		Persisted: &storagebuckets.StorageBucketPersisted{
			Data: secrets,
		},
	}, nil
}

func (l *LoopbackStorage) onUpdateStorageBucket(ctx context.Context, req *plgpb.OnUpdateStorageBucketRequest) (*plgpb.OnUpdateStorageBucketResponse, error) {
	const op = "loopback.(LoopbackStorage).onUpdateStorageBucket"
	if req == nil {
		return nil, status.Errorf(codes.InvalidArgument, "%s: request is nil", op)
	}
	if req.GetNewBucket() == nil {
		return nil, status.Errorf(codes.InvalidArgument, "%s: missing storage bucket", op)
	}
	if req.GetNewBucket().GetAttributes() == nil {
		return nil, status.Errorf(codes.InvalidArgument, "%s: missing attributes", op)
	}
	l.m.Lock()
	defer l.m.Unlock()
	if _, ok := l.buckets[BucketName(req.GetNewBucket().GetBucketName())]; !ok {
		return nil, status.Errorf(codes.NotFound, "%s: bucket not found", op)
	}
	for _, err := range l.errs {
		if err.match(req.GetNewBucket(), "", OnUpdateStorageBucket) {
			return nil, status.Errorf(err.ErrCode, "%s: %s", op, err.ErrMsg)
		}
	}
	secrets := &structpb.Struct{
		Fields: make(map[string]*structpb.Value),
	}
	var hasDynamicCreds bool
	attrs := req.GetNewBucket().GetAttributes()
	if attrs != nil {
		_, hasDynamicCreds = attrs.Fields[ConstDynamicCredentials]
	}
	var hasStaticCreds bool
	if req.GetNewBucket().GetSecrets() != nil && len(req.GetNewBucket().GetSecrets().AsMap()) > 0 {
		hasStaticCreds = true
		secrets = req.GetNewBucket().GetSecrets()
	}
	if hasDynamicCreds && hasStaticCreds {
		return nil, status.Errorf(codes.InvalidArgument, "%s: cannot use both dynamic and static credentials", op)
	}
	if !hasDynamicCreds && len(secrets.AsMap()) == 0 {
		if req.GetPersisted() != nil && req.GetPersisted().GetData() != nil && len(req.GetPersisted().GetData().AsMap()) > 0 {
			secrets = req.GetPersisted().GetData()
		}
	}
	return &plgpb.OnUpdateStorageBucketResponse{
		Persisted: &storagebuckets.StorageBucketPersisted{
			Data: secrets,
		},
	}, nil
}

func (l *LoopbackStorage) onDeleteStorageBucket(ctx context.Context, req *plgpb.OnDeleteStorageBucketRequest) (*plgpb.OnDeleteStorageBucketResponse, error) {
	const op = "loopback.(LoopbackStorage).onDeleteStorageBucket"
	if req == nil {
		return nil, status.Errorf(codes.InvalidArgument, "%s: request is nil", op)
	}
	if req.GetBucket() == nil {
		return nil, status.Errorf(codes.InvalidArgument, "%s: missing storage bucket", op)
	}
	if req.GetBucket().GetAttributes() == nil {
		return nil, status.Errorf(codes.InvalidArgument, "%s: missing attributes", op)
	}
	return &plgpb.OnDeleteStorageBucketResponse{}, nil
}

func (l *LoopbackStorage) validatePermissions(ctx context.Context, req *plgpb.ValidatePermissionsRequest) (*plgpb.ValidatePermissionsResponse, error) {
	const op = "loopback.(LoopbackStorage).validatePermissions"
	if req == nil {
		return nil, status.Errorf(codes.InvalidArgument, "%s: request is nil", op)
	}
	if req.GetBucket() == nil {
		return nil, status.Errorf(codes.InvalidArgument, "%s: missing storage bucket", op)
	}
	if req.GetBucket().GetAttributes() == nil {
		return nil, status.Errorf(codes.InvalidArgument, "%s: missing attributes", op)
	}
	l.m.Lock()
	defer l.m.Unlock()
	if _, ok := l.buckets[BucketName(req.GetBucket().GetBucketName())]; !ok {
		return nil, status.Errorf(codes.NotFound, "%s: bucket not found", op)
	}

	for _, err := range l.errs {
		if err.match(req.GetBucket(), "", ValidatePermissions) {
			if err.StorageBucketCredentialState != nil {
				return nil, createErrorWithBucketCredentialState(err.ErrCode, fmt.Sprintf("%s: %s", op, err.ErrMsg), err.StorageBucketCredentialState)
			}
			return nil, status.Errorf(err.ErrCode, "%s: %s", op, err.ErrMsg)
		}
	}
	return &plgpb.ValidatePermissionsResponse{}, nil
}

func (l *LoopbackStorage) headObject(ctx context.Context, req *plgpb.HeadObjectRequest) (*plgpb.HeadObjectResponse, error) {
	const op = "loopback.(LoopbackStorage).headObject"
	if req == nil {
		return nil, status.Errorf(codes.InvalidArgument, "%s: request is nil", op)
	}
	if req.GetBucket() == nil {
		return nil, status.Errorf(codes.InvalidArgument, "$%s: missing storage bucket", op)
	}
	if req.GetBucket().GetAttributes() == nil {
		return nil, status.Errorf(codes.InvalidArgument, "%s: missing attributes", op)
	}
	if req.GetKey() == "" {
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
		if err.match(req.GetBucket(), req.GetKey(), HeadObject) {
			if err.StorageBucketCredentialState != nil {
				return nil, createErrorWithBucketCredentialState(err.ErrCode, fmt.Sprintf("%s: %s", op, err.ErrMsg), err.StorageBucketCredentialState)
			}
			return nil, status.Errorf(err.ErrCode, "%s: %s", op, err.ErrMsg)
		}
	}
	var contentLength int64
	if object.contentLength != nil {
		contentLength = *object.contentLength
	}
	return &plgpb.HeadObjectResponse{
		ContentLength: contentLength,
		LastModified:  timestamppb.New(*object.lastModified),
	}, nil
}

func (l *LoopbackStorage) getObject(req *plgpb.GetObjectRequest, stream plgpb.StoragePluginService_GetObjectServer) error {
	const op = "loopback.(LoopbackStorage).getObject"
	if req == nil {
		return status.Errorf(codes.InvalidArgument, "%s: request is nil", op)
	}
	if req.GetBucket() == nil {
		return status.Errorf(codes.InvalidArgument, "%s: missing storage bucket", op)
	}
	if req.GetBucket().GetAttributes() == nil {
		return status.Errorf(codes.InvalidArgument, "%s: missing attributes", op)
	}
	if req.GetKey() == "" {
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
		if err.match(req.GetBucket(), req.GetKey(), GetObject) {
			if err.StorageBucketCredentialState != nil {
				return createErrorWithBucketCredentialState(err.ErrCode, fmt.Sprintf("%s: %s", op, err.ErrMsg), err.StorageBucketCredentialState)
			}
			return status.Errorf(err.ErrCode, "%s: %s", op, err.ErrMsg)
		}
	}
	go func() {
		chunkSize := req.GetChunkSize()
		if chunkSize == 0 {
			chunkSize = defaultStreamChunkSize
		}
		data := []byte{}
		for _, chunk := range object.DataChunks {
			data = append(data, chunk...)
		}
		for i := 0; i < len(data); i += int(chunkSize) {
			end := i + int(chunkSize)
			if end > len(data) {
				end = len(data)
			}
			if err := stream.Send(&plgpb.GetObjectResponse{
				FileChunk: append([]byte{}, data[i:end]...),
			}); err != nil {
				stream.SendMsg(status.Errorf(codes.Internal, "%s: failed to send object data: %v", op, err))
				return
			}
		}
		stream.SendMsg(io.EOF)
	}()
	return nil
}

func (l *LoopbackStorage) putObject(ctx context.Context, req *plgpb.PutObjectRequest) (*plgpb.PutObjectResponse, error) {
	const op = "loopback.(LoopbackStorage).putObject"
	if req == nil {
		return nil, status.Errorf(codes.InvalidArgument, "%s: request is nil", op)
	}
	if req.GetBucket() == nil {
		return nil, status.Errorf(codes.InvalidArgument, "%s: missing storage bucket", op)
	}
	if req.GetBucket().GetAttributes() == nil {
		return nil, status.Errorf(codes.InvalidArgument, "%s: missing attributes", op)
	}
	if req.GetBucket().GetBucketName() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "%s: missing bucket name", op)
	}
	if req.GetKey() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "%s; missing object key", op)
	}
	if req.GetPath() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "%s; missing path", op)
	}
	info, err := os.Stat(req.Path)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%s: file check failed: %v", op, err)
	}
	if info == nil {
		return nil, status.Errorf(codes.Internal, "%s: failed to get file info", op)
	}
	if info.IsDir() {
		return nil, status.Errorf(codes.InvalidArgument, "%s: path is a directory", op)
	}
	l.m.Lock()
	defer l.m.Unlock()
	bucket, ok := l.buckets[BucketName(req.GetBucket().GetBucketName())]
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "%s: bucket not found", op)
	}
	// return an expected mock error if one was provided
	for _, err := range l.errs {
		if err.match(req.GetBucket(), req.GetKey(), PutObject) {
			if err.StorageBucketCredentialState != nil {
				return nil, createErrorWithBucketCredentialState(err.ErrCode, fmt.Sprintf("%s: %s", op, err.ErrMsg), err.StorageBucketCredentialState)
			}
			return nil, status.Errorf(err.ErrCode, "%s: %s", op, err.ErrMsg)
		}
	}
	// return an expected mock response if one was provided
	for _, mock := range l.putObjectResponse {
		if mock.match(req.GetBucket(), req.GetKey()) {
			return mock.Response, nil
		}
	}

	lastModified := time.Now()
	objectData, err := os.ReadFile(req.Path)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%s: failed to read file", op)
	}
	if len(objectData) == 0 {
		return nil, status.Errorf(codes.InvalidArgument, "%s: missing object data", op)
	}
	contentLength := int64(len(objectData))

	objectChunks := []Chunk{}
	for i := 0; i < len(objectData); i = i + l.chunksSize {
		j := i + l.chunksSize
		if j > len(objectData) {
			j = len(objectData)
		}
		objectChunks = append(objectChunks, copyBytes(objectData[i:j]))
	}

	// Now insert the object
	objectPath := ObjectName(path.Join(req.GetBucket().GetBucketPrefix(), req.GetKey()))
	bucket[objectPath] = &storagePluginStorageInfo{
		DataChunks:    objectChunks,
		contentLength: &contentLength,
		lastModified:  &lastModified,
	}

	hash := sha256.New()
	if _, err := io.Copy(hash, bytes.NewReader(objectData)); err != nil {
		return nil, status.Errorf(codes.Internal, "%s: failed to hash object: %v", op, err)
	}

	return &plgpb.PutObjectResponse{
		ChecksumSha_256: hash.Sum(nil),
	}, nil
}

func (l *LoopbackStorage) deleteObjects(ctx context.Context, req *plgpb.DeleteObjectsRequest) (*plgpb.DeleteObjectsResponse, error) {
	const op = "loopback.(LoopbackStorage).deleteObjects"
	if req == nil {
		return nil, status.Errorf(codes.InvalidArgument, "%s: request is nil", op)
	}
	if req.GetBucket() == nil {
		return nil, status.Errorf(codes.InvalidArgument, "%s: missing storage bucket", op)
	}
	if req.GetBucket().GetAttributes() == nil {
		return nil, status.Errorf(codes.InvalidArgument, "%s: missing attributes", op)
	}
	if req.GetKeyPrefix() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "%s; missing key prefix", op)
	}
	l.m.Lock()
	defer l.m.Unlock()
	bucket, ok := l.buckets[BucketName(req.GetBucket().GetBucketName())]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "%s: bucket not found", op)
	}
	for _, err := range l.errs {
		if err.match(req.GetBucket(), req.GetKeyPrefix(), DeleteObjects) {
			return nil, status.Errorf(err.ErrCode, "%s: %s", op, err.ErrMsg)
		}
	}
	prefix := ObjectName(req.GetBucket().GetBucketPrefix() + req.GetKeyPrefix())
	var deleted uint32 = 0
	if req.GetRecursive() {
		for key := range bucket {
			if strings.HasPrefix(string(key), string(prefix)) {
				delete(bucket, key)
				deleted++
			}
		}
	} else {
		_, ok := bucket[prefix]
		if ok {
			delete(bucket, prefix)
		}
		deleted++ // this is outside the if statement because aws always returns a success
	}
	return &plgpb.DeleteObjectsResponse{
		ObjectsDeleted: deleted,
	}, nil
}

// CloneBucket returns a clone of the bucket.
// returns nil when the bucket is not found.
func (l *LoopbackStorage) CloneBucket(name string) Bucket {
	l.m.Lock()
	defer l.m.Unlock()
	if _, ok := l.buckets[BucketName(name)]; !ok {
		return nil
	}
	bucket := Bucket{}
	for objName, obj := range l.buckets[BucketName(name)] {
		if obj != nil {
			bucket[objName] = copyStorageInfo(obj)
		}
	}
	return bucket
}

// CloneStorageInfo returns a clone of the object stored in memory.
// Returns nil when the bucket or object is not found.
func (l *LoopbackStorage) CloneStorageInfo(bucketName, objectName string) *storagePluginStorageInfo {
	l.m.Lock()
	defer l.m.Unlock()
	bucket, ok := l.buckets[BucketName(bucketName)]
	if !ok {
		return nil
	}
	obj, ok := bucket[ObjectName(objectName)]
	if !ok {
		return nil
	}
	return copyStorageInfo(obj)
}

func copyStorageInfo(obj *storagePluginStorageInfo) *storagePluginStorageInfo {
	chunks := make([]Chunk, len(obj.DataChunks))
	for i, c := range obj.DataChunks {
		chunks[i] = copyBytes(c)
	}
	contentLength := *obj.contentLength
	lastModified := *obj.lastModified
	return &storagePluginStorageInfo{
		DataChunks:    chunks,
		lastModified:  &lastModified,
		contentLength: &contentLength,
	}
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

func createErrorWithBucketCredentialState(errCode codes.Code, msg string, sbcState *plgpb.StorageBucketCredentialState) error {
	st := status.New(errCode, msg)
	stWithDetails, stErr := st.WithDetails(sbcState)
	if stErr == nil {
		st = stWithDetails
	}
	return st.Err()
}
