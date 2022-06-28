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
		want          *store.WorkerTag
		wantCreateErr bool
	}{
		{
			name: "success api source",
			want: &store.WorkerTag{
				WorkerId: worker.GetPublicId(),
				Key:      "key",
				Value:    "value",
				Source:   ApiTagSource.String(),
			},
		},
		{
			name: "success config source",
			want: &store.WorkerTag{
				WorkerId: worker.GetPublicId(),
				Key:      "key",
				Value:    "value",
				Source:   ConfigurationTagSource.String(),
			},
		},
		{
			name: "unknown source",
			want: &store.WorkerTag{
				WorkerId: worker.GetPublicId(),
				Key:      "key",
				Value:    "value",
				Source:   "unknown",
			},
			wantCreateErr: true,
		},
		{
			name: "no source",
			want: &store.WorkerTag{
				WorkerId: worker.GetPublicId(),
				Key:      "key",
				Value:    "value",
			},
			wantCreateErr: true,
		},
		{
			name: "bad worker id",
			want: &store.WorkerTag{
				WorkerId: "w_badworkeridthatdoesntexist",
				Key:      "key",
				Value:    "value",
			},
			wantCreateErr: true,
		},
		{
			name: "missing worker id",
			want: &store.WorkerTag{
				Key:   "key",
				Value: "value",
			},
			wantCreateErr: true,
		},
		{
			name: "missing key",
			want: &store.WorkerTag{
				WorkerId: worker.GetPublicId(),
				Value:    "value",
			},
			wantCreateErr: true,
		},
		{
			name: "missing value",
			want: &store.WorkerTag{
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
}

func makeTagsList(tags ...*Tag) []*Tag {
	var tagsList []*Tag
	for _, t := range tags {
		tagsList = append(tagsList, t)
	}
	return tagsList
}

func TestRepository_AddWorkerTags(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	assert, require := assert.New(t), require.New(t)
	repo, err := NewRepository(rw, rw, kms)
	require.NoError(err)
	require.NotNil(repo)
	worker := TestKmsWorker(t, conn, wrapper)
	// add another worker here to avoid issue with worker version input being locked in at compile time
	worker2 := TestKmsWorker(t, conn, wrapper)

	type args struct {
		publicId string
		version  uint32
		ts       TagSource
		tags     []*Tag
		opt      []Option
	}

	tests := []struct {
		name            string
		args            args
		want            []*Tag
		wantIsErr       errors.Code
		wantErrContains string
	}{
		{
			name: "invalid-tagsource",
			args: args{
				publicId: worker.PublicId,
				version:  worker.Version,
				ts:       "invalid_tagsource",
				tags: makeTagsList(&Tag{
					Key:   "key",
					Value: "value",
				}),
			},
			wantIsErr:       errors.InvalidParameter,
			wantErrContains: "invalid tag source provided",
		},
		{
			name: "empty-public-id",
			args: args{
				publicId: "",
				version:  worker.Version,
				ts:       ApiTagSource,
				tags: makeTagsList(&Tag{
					Key:   "key",
					Value: "value",
				}),
			},
			wantIsErr:       errors.InvalidParameter,
			wantErrContains: "worker public id is empty",
		},
		{
			name: "zero-version",
			args: args{
				publicId: worker.PublicId,
				version:  0,
				ts:       ApiTagSource,
				tags: makeTagsList(&Tag{
					Key:   "key",
					Value: "value",
				}),
			},
			wantIsErr:       errors.InvalidParameter,
			wantErrContains: "missing version",
		},
		{
			name: "nil-tags",
			args: args{
				publicId: worker.PublicId,
				version:  worker.Version,
				ts:       ApiTagSource,
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
				ts:       ApiTagSource,
				tags: makeTagsList(&Tag{
					Key:   "key",
					Value: "value",
				}),
			},
			want: makeTagsList(&Tag{
				Key:   "key",
				Value: "value",
			}),
		},
		{
			name: "add-many-tags",
			args: args{
				publicId: worker2.PublicId,
				version:  worker2.Version,
				ts:       ApiTagSource,
				tags: makeTagsList(
					&Tag{
						Key:   "key",
						Value: "value",
					},
					&Tag{
						Key:   "key2",
						Value: "value2",
					},
					&Tag{
						Key:   "key3",
						Value: "value3",
					}),
			},
			want: makeTagsList(
				&Tag{
					Key:   "key",
					Value: "value",
				},
				&Tag{
					Key:   "key2",
					Value: "value2",
				},
				&Tag{
					Key:   "key3",
					Value: "value3",
				}),
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {

			got, err := repo.AddWorkerTags(context.Background(), tt.args.publicId, tt.args.version, tt.args.ts, tt.args.tags)
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

func TestRepository_SetWorkerTags(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	worker := TestKmsWorker(t, conn, wrapper)
	// add another worker here to avoid issue with worker version input being locked in at compile time
	worker2 := TestKmsWorker(t, conn, wrapper)

	assert, require := assert.New(t), require.New(t)
	repo, err := NewRepository(rw, rw, kms)
	require.NoError(err)
	require.NotNil(repo)

	type args struct {
		publicId string
		version  uint32
		ts       TagSource
		tags     []*Tag
		opt      []Option
	}

	tests := []struct {
		name            string
		args            args
		want            []*Tag
		wantIsErr       errors.Code
		wantErrContains string
	}{
		{
			name: "invalid-tagsource",
			args: args{
				publicId: worker.PublicId,
				version:  worker.Version,
				ts:       "invalid_tagsource",
				tags: makeTagsList(&Tag{
					Key:   "key",
					Value: "value",
				}),
			},
			wantIsErr:       errors.InvalidParameter,
			wantErrContains: "invalid tag source provided",
		},
		{
			name: "empty-public-id",
			args: args{
				publicId: "",
				version:  worker.Version,
				ts:       ApiTagSource,
				tags: makeTagsList(&Tag{
					Key:   "key",
					Value: "value",
				}),
			},
			wantIsErr:       errors.InvalidParameter,
			wantErrContains: "worker public id is empty",
		},
		{
			name: "zero-version",
			args: args{
				publicId: worker.PublicId,
				version:  0,
				ts:       ApiTagSource,
				tags: makeTagsList(&Tag{
					Key:   "key",
					Value: "value",
				}),
			},
			wantIsErr:       errors.InvalidParameter,
			wantErrContains: "missing version",
		},
		{
			name: "set-nil-tags",
			args: args{
				publicId: worker.PublicId,
				version:  worker.Version,
				ts:       ApiTagSource,
				tags:     nil,
			},
			want: nil,
		},
		{
			name: "set-many-tags",
			args: args{
				publicId: worker2.PublicId,
				version:  worker2.Version,
				ts:       ApiTagSource,
				tags: makeTagsList(
					&Tag{
						Key:   "key",
						Value: "value",
					},
					&Tag{
						Key:   "key2",
						Value: "value2",
					},
					&Tag{
						Key:   "key3",
						Value: "value3",
					}),
			},
			want: makeTagsList(
				&Tag{
					Key:   "key",
					Value: "value",
				},
				&Tag{
					Key:   "key2",
					Value: "value2",
				},
				&Tag{
					Key:   "key3",
					Value: "value3",
				}),
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {

			got, err := repo.SetWorkerTags(context.Background(), tt.args.publicId, tt.args.version, tt.args.ts, tt.args.tags)
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
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	worker := TestKmsWorker(t, conn, wrapper)

	assert, require := assert.New(t), require.New(t)
	repo, err := NewRepository(rw, rw, kms)
	require.NoError(err)
	require.NotNil(repo)

	type args struct {
		publicId string
		version  uint32
		ts       TagSource
		tags     []*Tag
		opt      []Option
	}

	tests := []struct {
		name            string
		args            args
		want            []*Tag
		wantIsErr       errors.Code
		wantErrContains string
	}{
		{
			name: "invalid-tagsource",
			args: args{
				publicId: worker.PublicId,
				version:  worker.Version,
				ts:       "invalid_tagsource",
				tags: makeTagsList(&Tag{
					Key:   "key",
					Value: "value",
				}),
			},
			wantIsErr:       errors.InvalidParameter,
			wantErrContains: "invalid tag source provided",
		},
		{
			name: "empty-public-id",
			args: args{
				publicId: "",
				version:  worker.Version,
				ts:       ApiTagSource,
				tags: makeTagsList(&Tag{
					Key:   "key",
					Value: "value",
				}),
			},
			wantIsErr:       errors.InvalidParameter,
			wantErrContains: "worker public id is empty",
		},
		{
			name: "zero-version",
			args: args{
				publicId: worker.PublicId,
				version:  0,
				ts:       ApiTagSource,
				tags: makeTagsList(&Tag{
					Key:   "key",
					Value: "value",
				}),
			},
			wantIsErr:       errors.InvalidParameter,
			wantErrContains: "missing version",
		},
		{
			name: "nil-tags",
			args: args{
				publicId: worker.PublicId,
				version:  worker.Version,
				ts:       ApiTagSource,
				tags:     nil,
			},
			wantIsErr:       errors.InvalidParameter,
			wantErrContains: "no tags provided",
		},
		// Note: actual delete operation testcases are found in subsequent func TestRepository_WorkerTagsConsequent
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {

			got, err := repo.DeleteWorkerTags(context.Background(), tt.args.publicId, tt.args.version, tt.args.ts, tt.args.tags)
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
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(rw, rw, kms)
	require.NoError(err)
	require.NotNil(repo)

	worker := TestKmsWorker(t, conn, wrapper)
	manyTags := makeTagsList(
		&Tag{
			Key:   "key",
			Value: "value",
		},
		&Tag{
			Key:   "key2",
			Value: "value2",
		},
		&Tag{
			Key:   "key3",
			Value: "value3",
		})
	added, err := repo.AddWorkerTags(context.Background(), worker.PublicId, worker.Version, ApiTagSource, manyTags)
	assert.NoError(err)
	assert.Equal(manyTags, added)

	worker, err = repo.LookupWorker(context.Background(), worker.PublicId)
	require.NoError(err)
	assert.Equal(uint32(2), worker.Version)

	// TODO: add tests for adding multiple of the same tag

	// TODO: delete some tags, verify behavior, append new tags, and then set tags to nil

}
