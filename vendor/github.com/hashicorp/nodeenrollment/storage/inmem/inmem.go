// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package inmem

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	"github.com/armon/go-radix"
	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/types"
	"google.golang.org/protobuf/proto"
)

// These paths are used for different kinds of storage
const (
	rootsSubPath                 = "roots"
	nodeInfoSubPath              = "nodeinfo"
	nodeCredsSubPath             = "nodecreds"
	serverLedActivationTokenPath = "serverledactivationtokens"
)

var _ nodeenrollment.Storage = (*Storage)(nil)

// InmemBackend is an in-memory only physical backend. It is useful
// for testing and development situations where the data is not
// expected to be durable.
type Storage struct {
	sync.RWMutex
	root *radix.Tree
}

// New creates a new object that implements the Storage interface in memory. It
// is thread-safe.
func New(ctx context.Context) (*Storage, error) {
	return &Storage{
		root: radix.New(),
	}, nil
}

// subPathFromMsg determines what subdirectory to use based on which message
// type it is
func subPathFromMsg(msg proto.Message) (string, error) {
	const op = "nodeenrollment.storage.inmem.(Storage).subPathFromMsg"
	switch t := msg.(type) {
	case *types.NodeCredentials:
		return nodeCredsSubPath, nil
	case *types.NodeInformation:
		return nodeInfoSubPath, nil
	case *types.RootCertificates:
		return rootsSubPath, nil
	case *types.ServerLedActivationToken:
		return serverLedActivationTokenPath, nil
	default:
		return "", fmt.Errorf("(%s) unknown message type %T", op, t)
	}
}

// Store implements the Storage interface.
//
// If the message already exists, it is overwritten.
func (ts *Storage) Store(ctx context.Context, msg nodeenrollment.MessageWithId) error {
	const op = "nodeenrollment.storage.inmem.(Storage).Store"
	if err := types.ValidateMessage(msg); err != nil {
		return fmt.Errorf("(%s) given message cannot be stored: %w", op, err)
	}
	subPath, err := subPathFromMsg(msg)
	if err != nil {
		return fmt.Errorf("(%s) given message cannot be stored: %w", op, err)
	}
	return ts.storeValue(ctx, msg.GetId(), subPath, msg)
}

// Load implements the Storage interface
func (ts *Storage) Load(ctx context.Context, msg nodeenrollment.MessageWithId) error {
	const op = "nodeenrollment.storage.inmem.(Storage).Load"
	if err := types.ValidateMessage(msg); err != nil {
		return fmt.Errorf("(%s) given message cannot be loaded: %w", op, err)
	}
	subPath, err := subPathFromMsg(msg)
	if err != nil {
		return fmt.Errorf("(%s) given message cannot be loaded: %w", op, err)
	}
	err = ts.loadValue(ctx, msg.GetId(), subPath, msg)
	if err != nil {
		return fmt.Errorf("(%s) given message cannot be loaded: %w", op, err)
	}
	return nil
}

// Remove implements the Storage interface
func (ts *Storage) Remove(ctx context.Context, msg nodeenrollment.MessageWithId) error {
	const op = "nodeenrollment.storage.inmem.(Storage).Remove"
	if err := types.ValidateMessage(msg); err != nil {
		return fmt.Errorf("(%s) given message cannot be removed: %w", op, err)
	}
	subPath, err := subPathFromMsg(msg)
	if err != nil {
		return fmt.Errorf("(%s) given message cannot be removed: %w", op, err)
	}
	return ts.removeValue(ctx, msg.GetId(), subPath)
}

// List implements the Storage interface
func (ts *Storage) List(ctx context.Context, msg proto.Message) ([]string, error) {
	const op = "nodeenrollment.storage.file.(Storage).List"

	switch t := msg.(type) {
	case *types.NodeCredentials,
		*types.NodeInformation,
		*types.RootCertificates:
	default:
		return nil, fmt.Errorf("(%s) unknown message type %T", op, t)
	}

	subPath, err := subPathFromMsg(msg)
	if err != nil {
		return nil, fmt.Errorf("(%s) given messages cannot be listed: %w", op, err)
	}
	return ts.listValues(ctx, subPath)
}

// storeValue is the general function called to store values, taking in an id,
// subpath, and proto message to store
func (ts *Storage) storeValue(ctx context.Context, id, subPath string, msg proto.Message) error {
	switch {
	case id == "":
		return errors.New("no id given when storing value")
	case subPath == "":
		return errors.New("no sub path given when storing value")
	case msg == nil:
		return errors.New("nil msg when storing value")
	}

	path := subPath + string(filepath.Separator) + id

	marshaledBytes, err := proto.Marshal(msg)
	if err != nil {
		return fmt.Errorf("error proto marshaling value: %w", err)
	}

	ts.Lock()
	defer ts.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	ts.root.Insert(path, marshaledBytes)
	return nil
}

// loadValue is the general function for loading a value into the given result
func (ts *Storage) loadValue(ctx context.Context, id, subPath string, result proto.Message) error {
	switch {
	case id == "":
		return errors.New("no id given when loading value")
	case subPath == "":
		return errors.New("no sub path given when loading value")
	case result == nil:
		return errors.New("nil result value when loading value")
	}

	path := subPath + string(filepath.Separator) + id

	ts.RLock()
	defer ts.RUnlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	val, found := ts.root.Get(path)
	if !found {
		return nodeenrollment.ErrNotFound
	}
	if err := proto.Unmarshal(val.([]byte), result); err != nil {
		return fmt.Errorf("error unmarshaling value at path %s: %w", path, err)
	}
	return nil
}

// removeValue is used to remove a message from storage
func (ts *Storage) removeValue(ctx context.Context, id, subPath string) error {
	switch {
	case id == "":
		return errors.New("no identifier given when removing value")
	case subPath == "":
		return errors.New("no subPath given when removing value")
	}

	path := subPath + string(filepath.Separator) + id

	ts.Lock()
	defer ts.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	ts.root.Delete(path)

	return nil
}

// listValues is used to list values in a subpath
func (ts *Storage) listValues(ctx context.Context, subPath string) ([]string, error) {
	if subPath == "" {
		return nil, errors.New("no subPath given when removing value")
	}

	ts.RLock()
	defer ts.RUnlock()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	allEntries := ts.root.ToMap()
	paths := make([]string, 0, len(allEntries))
	for k := range allEntries {
		prefix := subPath + string(filepath.Separator)
		if strings.HasPrefix(k, prefix) {
			paths = append(paths, strings.TrimPrefix(k, prefix))
		}
	}

	return paths, nil
}
