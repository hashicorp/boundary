// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/server/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWorkerTags_Create(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	rw := db.New(conn)

	worker := TestKmsWorker(t, conn, wrapper)

	tests := []struct {
		name          string
		want          *store.ApiTag
		wantCreateErr bool
	}{
		{
			name: "success- api tag",
			want: &store.ApiTag{
				WorkerId: worker.GetPublicId(),
				Key:      "key",
				Value:    "value",
			},
		},
		{
			name: "bad worker id",
			want: &store.ApiTag{
				WorkerId: "w_badworkeridthatdoesntexist",
				Key:      "key",
				Value:    "value",
			},
			wantCreateErr: true,
		},
		{
			name: "missing worker id",
			want: &store.ApiTag{
				Key:   "key",
				Value: "value",
			},
			wantCreateErr: true,
		},
		{
			name: "missing key",
			want: &store.ApiTag{
				WorkerId: worker.GetPublicId(),
				Value:    "value",
			},
			wantCreateErr: true,
		},
		{
			name: "missing value",
			want: &store.ApiTag{
				WorkerId: worker.GetPublicId(),
				Key:      "key",
			},
			wantCreateErr: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			err := rw.Create(context.Background(), tt.want)
			if tt.wantCreateErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}

	// Create a config tag
	configTag := &store.ConfigTag{
		WorkerId: worker.GetPublicId(),
		Key:      "key",
		Value:    "value",
	}
	err := rw.Create(context.Background(), configTag)
	assert.NoError(t, err)
}

func TestRepository_AddWorkerTags(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	assert, require := assert.New(t), require.New(t)
	repo, err := NewRepository(ctx, rw, rw, kms)
	require.NoError(err)
	require.NotNil(repo)
	// WithWorkerTags sets config tags to ensure they are not affected by api tag operations
	worker := TestKmsWorker(t, conn, wrapper, WithWorkerTags(&Tag{Key: "key_c", Value: "value_c"}))

	type args struct {
		publicId string
		version  uint32
		tags     []*Tag
	}

	tests := []struct {
		name            string
		args            args
		want            []*Tag
		wantIsErr       errors.Code
		wantErrContains string
	}{
		{
			name: "empty-public-id",
			args: args{
				publicId: "",
				version:  worker.Version,
				tags: []*Tag{{
					Key:   "key",
					Value: "value",
				}},
			},
			wantIsErr:       errors.InvalidParameter,
			wantErrContains: "worker public id is empty",
		},
		{
			name: "zero-version",
			args: args{
				publicId: worker.PublicId,
				version:  0,
				tags: []*Tag{{
					Key:   "key",
					Value: "value",
				}},
			},
			wantIsErr:       errors.InvalidParameter,
			wantErrContains: "missing version",
		},
		{
			name: "bad-version",
			args: args{
				publicId: worker.PublicId,
				version:  100,
				tags: []*Tag{{
					Key:   "key",
					Value: "value",
				}},
			},
			wantIsErr:       errors.MultipleRecords,
			wantErrContains: "updated worker version and 0 rows updated",
		},
		{
			name: "nil-tags",
			args: args{
				publicId: worker.PublicId,
				version:  worker.Version,
				tags:     nil,
			},
			wantIsErr:       errors.InvalidParameter,
			wantErrContains: "no tags provided",
		},
		{
			name: "add-valid-tag",
			args: args{
				publicId: worker.PublicId,
				version:  worker.Version,
				tags: []*Tag{{
					Key:   "key",
					Value: "value",
				}},
			},
			want: []*Tag{{
				Key:   "key",
				Value: "value",
			}},
		},
		{
			name: "add-many-tags",
			args: func() args {
				// reset test worker to avoid worker version conflicts when running tests individually vs sequentially
				worker := TestKmsWorker(t, conn, wrapper, WithWorkerTags(&Tag{Key: "key_c", Value: "value_c"}))
				return args{
					publicId: worker.PublicId,
					version:  worker.Version,
					tags: []*Tag{
						{
							Key:   "key",
							Value: "value",
						},
						{
							Key:   "key2",
							Value: "value2",
						},
						{
							Key:   "key3",
							Value: "value3",
						},
					},
				}
			}(),
			want: []*Tag{
				{
					Key:   "key",
					Value: "value",
				},
				{
					Key:   "key2",
					Value: "value2",
				},
				{
					Key:   "key3",
					Value: "value3",
				},
			},
		},
		{
			name: "add-preexisting-config-tags",
			args: func() args {
				worker := TestKmsWorker(t, conn, wrapper, WithWorkerTags(&Tag{Key: "key_c", Value: "value_c"}))
				return args{
					publicId: worker.PublicId,
					version:  worker.Version,
					tags: []*Tag{{
						Key:   "key_c",
						Value: "value_c",
					}},
				}
			}(),
			want: []*Tag{{
				Key:   "key_c",
				Value: "value_c",
			}},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got, err := repo.AddWorkerTags(context.Background(), tt.args.publicId, tt.args.version, tt.args.tags)
			if tt.wantErrContains != "" {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "want err: %q got: %q", tt.wantIsErr, err)
				assert.Contains(err.Error(), tt.wantErrContains)
				if tt.args.publicId != "" {
					repoWorker, err := repo.LookupWorker(context.Background(), tt.args.publicId)
					require.NoError(err)
					assert.Equal(uint32(1), repoWorker.Version)
				}
				return
			}
			assert.NoError(err)
			assert.ElementsMatch(tt.want, got.convertToTag())
			repoWorker, err := repo.LookupWorker(context.Background(), tt.args.publicId)
			require.NoError(err)
			assert.Equal(tt.args.version+1, repoWorker.Version)
		})
	}
}

func TestRepository_SetWorkerTags(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	worker := TestKmsWorker(t, conn, wrapper, WithWorkerTags(&Tag{Key: "key_c", Value: "value_c"}))

	assert, require := assert.New(t), require.New(t)
	repo, err := NewRepository(ctx, rw, rw, kms)
	require.NoError(err)
	require.NotNil(repo)

	type args struct {
		publicId string
		version  uint32
		tags     []*Tag
	}

	tests := []struct {
		name            string
		args            args
		want            []*Tag
		wantIsErr       errors.Code
		wantErrContains string
	}{
		{
			name: "empty-public-id",
			args: args{
				publicId: "",
				version:  worker.Version,
				tags: []*Tag{{
					Key:   "key",
					Value: "value",
				}},
			},
			wantIsErr:       errors.InvalidParameter,
			wantErrContains: "worker public id is empty",
		},
		{
			name: "zero-version",
			args: args{
				publicId: worker.PublicId,
				version:  0,
				tags: []*Tag{{
					Key:   "key",
					Value: "value",
				}},
			},
			wantIsErr:       errors.InvalidParameter,
			wantErrContains: "missing version",
		},
		{
			name: "bad-version",
			args: args{
				publicId: worker.PublicId,
				version:  100,
				tags: []*Tag{{
					Key:   "key",
					Value: "value",
				}},
			},
			wantIsErr:       errors.MultipleRecords,
			wantErrContains: "updated worker version and 0 rows updated",
		},
		{
			name: "set-nil-tags",
			args: args{
				publicId: worker.PublicId,
				version:  worker.Version,
				tags:     nil,
			},
			want: nil,
		},
		{
			name: "set-many-tags",
			args: func() args {
				worker := TestKmsWorker(t, conn, wrapper, WithWorkerTags(&Tag{Key: "key_c", Value: "value_c"}))
				return args{
					publicId: worker.PublicId,
					version:  worker.Version,
					tags: []*Tag{
						{
							Key:   "key",
							Value: "value",
						},
						{
							Key:   "key2",
							Value: "value2",
						},
						{
							Key:   "key3",
							Value: "value3",
						},
					},
				}
			}(),
			want: []*Tag{
				{
					Key:   "key",
					Value: "value",
				},
				{
					Key:   "key2",
					Value: "value2",
				},
				{
					Key:   "key3",
					Value: "value3",
				},
			},
		},
		{
			name: "set-preexisting-config-tags",
			args: func() args {
				worker := TestKmsWorker(t, conn, wrapper, WithWorkerTags(&Tag{Key: "key_c", Value: "value_c"}))
				return args{
					publicId: worker.PublicId,
					version:  worker.Version,
					tags: []*Tag{{
						Key:   "key_c",
						Value: "value_c",
					}},
				}
			}(),
			want: []*Tag{{
				Key:   "key_c",
				Value: "value_c",
			}},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got, err := repo.SetWorkerTags(context.Background(), tt.args.publicId, tt.args.version, tt.args.tags)
			if tt.wantErrContains != "" {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "want err: %q got: %q", tt.wantIsErr, err)
				assert.Contains(err.Error(), tt.wantErrContains)
				if tt.args.publicId != "" {
					repoWorker, err := repo.LookupWorker(context.Background(), tt.args.publicId)
					require.NoError(err)
					assert.Equal(uint32(1), repoWorker.Version)
				}
				return
			}
			assert.NoError(err)
			assert.Equal(tt.want, got)
			repoWorker, err := repo.LookupWorker(context.Background(), tt.args.publicId)
			require.NoError(err)
			assert.Equal(tt.args.version+1, repoWorker.Version)
		})
	}
}

func TestRepository_DeleteWorkerTags(t *testing.T) {
	// Note: more delete operation testcases are found in subsequent func TestRepository_WorkerTagsConsequent
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	worker := TestKmsWorker(t, conn, wrapper)

	assert, require := assert.New(t), require.New(t)
	repo, err := NewRepository(ctx, rw, rw, kms)
	require.NoError(err)
	require.NotNil(repo)

	type args struct {
		publicId string
		version  uint32
		tags     []*Tag
	}

	tests := []struct {
		name            string
		args            args
		want            int
		wantIsErr       errors.Code
		wantErrContains string
	}{
		{
			name: "empty-public-id",
			args: args{
				publicId: "",
				version:  worker.Version,
				tags: []*Tag{{
					Key:   "key",
					Value: "value",
				}},
			},
			wantIsErr:       errors.InvalidParameter,
			wantErrContains: "worker public id is empty",
		},
		{
			name: "zero-version",
			args: args{
				publicId: worker.PublicId,
				version:  0,
				tags: []*Tag{{
					Key:   "key",
					Value: "value",
				}},
			},
			wantIsErr:       errors.InvalidParameter,
			wantErrContains: "missing version",
		},
		{
			name: "bad-version",
			args: args{
				publicId: worker.PublicId,
				version:  100,
				tags: []*Tag{{
					Key:   "key",
					Value: "value",
				}},
			},
			wantIsErr:       errors.MultipleRecords,
			wantErrContains: "updated worker version and 0 rows updated",
		},
		{
			name: "nil-tags",
			args: args{
				publicId: worker.PublicId,
				version:  worker.Version,
				tags:     nil,
			},
			wantIsErr:       errors.InvalidParameter,
			wantErrContains: "no tags provided",
		},
		{
			name: "one-nil-tag",
			args: args{
				publicId: worker.PublicId,
				version:  worker.Version,
				tags: []*Tag{
					{
						Key:   "key",
						Value: "value",
					},
					nil,
				},
			},
			wantIsErr:       errors.InvalidParameter,
			wantErrContains: "found nil tag value in input",
		},
		{
			name: "nonexistent-tag",
			args: args{
				publicId: worker.PublicId,
				version:  worker.Version,
				tags: []*Tag{
					{
						Key:   "bad_key",
						Value: "bad_value",
					},
				},
			},
			wantIsErr:       errors.MultipleRecords,
			wantErrContains: "tags deleted 0 did not match request for 1",
		},
		{
			name: "valid-delete",
			args: func() args {
				worker := TestKmsWorker(t, conn, wrapper)
				_, err = repo.AddWorkerTags(context.Background(), worker.PublicId, worker.Version, []*Tag{
					{Key: "key", Value: "value"},
				})
				require.NoError(err)
				return args{
					publicId: worker.PublicId,
					version:  worker.Version + 1,
					tags: []*Tag{
						{
							Key:   "key",
							Value: "value",
						},
					},
				}
			}(),
			want: 1,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got, err := repo.DeleteWorkerTags(context.Background(), tt.args.publicId, tt.args.version, tt.args.tags)
			if tt.wantErrContains != "" {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "want err: %q got: %q", tt.wantIsErr, err)
				assert.Contains(err.Error(), tt.wantErrContains)
				if tt.args.publicId != "" {
					repoWorker, err := repo.LookupWorker(context.Background(), tt.args.publicId)
					require.NoError(err)
					assert.Equal(uint32(1), repoWorker.Version)
				}
				return
			}
			assert.NoError(err)
			assert.Equal(tt.want, got)
			repoWorker, err := repo.LookupWorker(context.Background(), tt.args.publicId)
			require.NoError(err)
			assert.Equal(tt.args.version+1, repoWorker.Version)
		})
	}
}

func TestRepository_WorkerTagsConsequent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(ctx, rw, rw, kms)
	require.NoError(err)
	require.NotNil(repo)

	// Create worker and set various overlapping config tags
	worker := TestKmsWorker(t, conn, wrapper, WithWorkerTags(
		&Tag{Key: "key", Value: "value"},
		&Tag{Key: "keykey", Value: "valval"},
		&Tag{Key: "key3", Value: "value3"},
		&Tag{Key: "key?", Value: "value?"}))

	// Add three valid tags to worker
	manyTags := []*Tag{
		{Key: "key", Value: "value"},
		{Key: "key2", Value: "value2"},
		{Key: "key3", Value: "value3"},
	}
	added, err := repo.AddWorkerTags(context.Background(), worker.PublicId, worker.Version, manyTags)
	assert.NoError(err)
	assert.ElementsMatch(manyTags, added.convertToTag())
	worker, err = repo.LookupWorker(context.Background(), worker.PublicId)
	require.NoError(err)
	assert.Equal(uint32(2), worker.Version)

	// Test adding a duplicate tag
	added, err = repo.AddWorkerTags(context.Background(), worker.PublicId, worker.Version, []*Tag{
		{Key: "key", Value: "value"},
	})
	assert.Error(err)
	assert.Contains(err.Error(), "duplicate key value violates unique constraint")
	assert.Nil(added)
	worker, err = repo.LookupWorker(context.Background(), worker.PublicId)
	require.NoError(err)
	assert.Equal(uint32(2), worker.Version)

	// Test adding/setting/deleting an invalid batch of tags
	invalidTags := []*Tag{
		{Key: "keya", Value: "valuea"},
		{Key: "keyb", Value: "valueb"},
		{Key: "keykey", Value: "valval"},
		{Key: "keykey", Value: "valval"},
	}
	added, err = repo.AddWorkerTags(context.Background(), worker.PublicId, worker.Version, invalidTags)
	assert.Contains(err.Error(), "duplicate key value violates unique constraint")
	assert.Nil(added)
	set, err := repo.SetWorkerTags(context.Background(), worker.PublicId, worker.Version, invalidTags)
	assert.Contains(err.Error(), "duplicate key value violates unique constraint")
	assert.Nil(set)
	rowsDeleted, err := repo.DeleteWorkerTags(context.Background(), worker.PublicId, worker.Version, invalidTags)
	assert.Contains(err.Error(), "tags deleted 0 did not match request for 4")
	assert.Equal(0, rowsDeleted)
	worker, err = repo.LookupWorker(context.Background(), worker.PublicId)
	require.NoError(err)
	assert.Equal(uint32(2), worker.Version)
	assert.Equal(len(manyTags), len(worker.ApiTags))

	// Delete a valid tag from worker
	rowsDeleted, err = repo.DeleteWorkerTags(context.Background(), worker.PublicId, worker.Version, []*Tag{
		{Key: "key3", Value: "value3"},
	})
	assert.Equal(1, rowsDeleted)
	assert.NoError(err)
	worker, err = repo.LookupWorker(context.Background(), worker.PublicId)
	require.NoError(err)
	assert.Equal(uint32(3), worker.Version)
	assert.Contains(worker.ApiTags.convertToTag(), &Tag{Key: "key", Value: "value"})
	assert.Contains(worker.ApiTags.convertToTag(), &Tag{Key: "key2", Value: "value2"})

	// Add another valid tag to worker
	_, err = repo.AddWorkerTags(context.Background(), worker.PublicId, worker.Version, []*Tag{
		{Key: "key!", Value: "value!"},
	})
	assert.NoError(err)
	worker, err = repo.LookupWorker(context.Background(), worker.PublicId)
	require.NoError(err)
	assert.Equal(uint32(4), worker.Version)
	assert.Contains(worker.ApiTags.convertToTag(), &Tag{Key: "key!", Value: "value!"})
	assert.Equal(3, len(worker.ApiTags))

	// Set all tags to nil
	set, err = repo.SetWorkerTags(context.Background(), worker.PublicId, worker.Version, nil)
	assert.Equal([]*Tag(nil), set)
	assert.NoError(err)
	worker, err = repo.LookupWorker(context.Background(), worker.PublicId)
	require.NoError(err)
	assert.Equal(uint32(5), worker.Version)
	assert.Equal(Tags(nil), worker.ApiTags)
	assert.Equal(0, len(worker.ApiTags))

	// Ensure config tags are untouched
	for _, ct := range []*Tag{
		{Key: "key", Value: "value"},
		{Key: "keykey", Value: "valval"},
		{Key: "key3", Value: "value3"},
		{Key: "key?", Value: "value?"},
	} {
		assert.Contains(worker.ConfigTags.convertToTag(), ct)
	}
	assert.Equal(4, len(worker.ConfigTags))

	// Go full circle
	_, err = repo.AddWorkerTags(context.Background(), worker.PublicId, worker.Version, manyTags)
	assert.NoError(err)
	worker, err = repo.LookupWorker(context.Background(), worker.PublicId)
	require.NoError(err)
	assert.Equal(uint32(6), worker.Version)
	assert.Equal(len(manyTags), len(worker.ApiTags))
	for _, t := range manyTags {
		assert.Contains(worker.ApiTags.convertToTag(), t)
	}
}
