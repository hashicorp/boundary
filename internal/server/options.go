// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"crypto/rand"
	"io"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/version"
	"github.com/hashicorp/nodeenrollment/types"
)

// getOpts - iterate the inbound Options and return a struct
func GetOpts(opt ...Option) options {
	opts := getDefaultOptions()
	for _, o := range opt {
		o(&opts)
	}
	return opts
}

// Option - how Options are passed as arguments
type Option func(*options)

// StorageBucketCredentialInfo defines the parameters to pass into the
// WithFilterWorkersByStorageBucketCredentialState option.
type StorageBucketCredentialInfo struct {
	CredentialId string
	Filters      []FilterStorageBucketCredentialStateFn
}

// options = how options are represented
type options struct {
	withName                                        string
	withPublicId                                    string
	withDescription                                 string
	withAddress                                     string
	withLimit                                       int
	withLiveness                                    time.Duration
	withUpdateTags                                  bool
	withWorkerTags                                  []*Tag
	withWorkerKeyIdentifier                         string
	withWorkerKeys                                  WorkerKeys
	withControllerEncryptionPrivateKey              []byte
	withKeyId                                       string
	withNonce                                       []byte
	withNewIdFunc                                   func(context.Context) (string, error)
	WithFetchNodeCredentialsRequest                 *types.FetchNodeCredentialsRequest
	withTestPkiWorkerAuthorized                     bool
	withTestPkiWorkerKeyId                          *string
	withTestUseInputTagsAsApiTags                   bool
	withWorkerType                                  WorkerType
	withRoot                                        RootInfo
	withStopAfter                                   uint
	WithCreateControllerLedActivationToken          bool
	withReleaseVersion                              string
	withOperationalState                            string
	withLocalStorageState                           string
	withActiveWorkers                               bool
	withFeature                                     version.Feature
	withDirectlyConnected                           bool
	withWorkerPool                                  []string
	withFilterWorkersByStorageBucketCredentialState *StorageBucketCredentialInfo
	withFilterWorkersByLocalStorageState            bool
	WithReader                                      db.Reader
	WithWriter                                      db.Writer
	withRandomReader                                io.Reader
}

func getDefaultOptions() options {
	return options{
		withNewIdFunc:         newWorkerId,
		withOperationalState:  ActiveOperationalState.String(),
		withLocalStorageState: UnknownWorkerType.String(),
		withRandomReader:      rand.Reader,
	}
}

// WithDescription provides an optional description.
func WithDescription(desc string) Option {
	return func(o *options) {
		o.withDescription = desc
	}
}

// WithName provides an optional name.
func WithName(name string) Option {
	return func(o *options) {
		o.withName = name
	}
}

// WithPublicId provides an optional public Id used for skipping one db call.
func WithPublicId(id string) Option {
	return func(o *options) {
		o.withPublicId = id
	}
}

// WithAddress provides an optional address.
func WithAddress(address string) Option {
	return func(o *options) {
		o.withAddress = address
	}
}

// WithLimit provides an option to provide a limit.  Intentionally allowing
// negative integers.   If WithLimit < 0, then unlimited results are returned.
// If WithLimit == 0, then default limits are used for results.
func WithLimit(limit int) Option {
	return func(o *options) {
		o.withLimit = limit
	}
}

// WithLiveness indicates how far back we want to search for server entries.
// Use 0 for the default liveness (15 seconds). A liveness value of -1 removes
// the liveliness condition.
func WithLiveness(liveness time.Duration) Option {
	return func(o *options) {
		o.withLiveness = liveness
	}
}

// WithUpdateTags indicates that we should perform tag updates in the DB.
// This would happen on first sync from a worker after startup or (eventually,
// perhaps), after a SIGHUP.
func WithUpdateTags(updateTags bool) Option {
	return func(o *options) {
		o.withUpdateTags = updateTags
	}
}

// WithWorkerTags provides worker tags.
func WithWorkerTags(tags ...*Tag) Option {
	return func(o *options) {
		newTags := []*Tag{}
		for _, tag := range tags {
			if tag != nil {
				newTags = append(newTags, tag)
			}
		}
		if len(newTags) > 0 {
			o.withWorkerTags = newTags
		}
	}
}

func WithWorkerKeyIdentifier(workerKeyIdentifier string) Option {
	return func(o *options) {
		o.withWorkerKeyIdentifier = workerKeyIdentifier
	}
}

func WithWorkerKeys(workerKeys WorkerKeys) Option {
	return func(o *options) {
		o.withWorkerKeys = workerKeys
	}
}

func WithControllerEncryptionPrivateKey(controllerKey []byte) Option {
	return func(o *options) {
		o.withControllerEncryptionPrivateKey = controllerKey
	}
}

func WithKeyId(keyId string) Option {
	return func(o *options) {
		o.withKeyId = keyId
	}
}

func WithNonce(nonce []byte) Option {
	return func(o *options) {
		o.withNonce = nonce
	}
}

// WithNewIdFunc allows an optional factory function for new worker IDs to be
// specified (this option is likely only useful for tests).
func WithNewIdFunc(fn func(context.Context) (string, error)) Option {
	return func(o *options) {
		o.withNewIdFunc = fn
	}
}

// WithFetchNodeCredentialsRequest allows an optional
// FetchNodeCredentialsRequest to be specified.
func WithFetchNodeCredentialsRequest(req *types.FetchNodeCredentialsRequest) Option {
	return func(o *options) {
		o.WithFetchNodeCredentialsRequest = req
	}
}

// WithTestPkiWorkerAuthorizedKeyId should only be used in tests.
// It specifies that the test worker should be authorized when returned and
// assigns the key id for that worker to the string pointer in this option.
func WithTestPkiWorkerAuthorizedKeyId(id *string) Option {
	return func(o *options) {
		o.withTestPkiWorkerAuthorized = true
		o.withTestPkiWorkerKeyId = id
	}
}

// WithTestUseInputTagsAsApiTags tells NewWorker to set the set of input tags as
// the api tags as well. This is useful for allowing a worker to have canonical
// tags without having to store worker information in the database.
func WithTestUseInputTagsAsApiTags(with bool) Option {
	return func(o *options) {
		o.withTestUseInputTagsAsApiTags = with
	}
}

// WithWorkerType allows specifying a particular type of worker (kms, pki)
// during lookup or listing
func WithWorkerType(with WorkerType) Option {
	return func(o *options) {
		o.withWorkerType = with
	}
}

// WithRoot provides an optional root node
func WithRoot(root RootInfo) Option {
	return func(o *options) {
		o.withRoot = root
	}
}

// WithStopAfter provides an optional stop after count
func WithStopAfter(stopAfter uint) Option {
	return func(o *options) {
		o.withStopAfter = stopAfter
	}
}

// WithCreateControllerLedActivationToken provides an optional stop after count
func WithCreateControllerLedActivationToken(with bool) Option {
	return func(o *options) {
		o.WithCreateControllerLedActivationToken = with
	}
}

// WithRelease version provides an optional release version
func WithReleaseVersion(version string) Option {
	return func(o *options) {
		o.withReleaseVersion = version
	}
}

// WithOperationalState provides an optional operational state.
func WithOperationalState(state string) Option {
	return func(o *options) {
		o.withOperationalState = state
	}
}

// WithActiveWorkers provides an optional filter to only include active workers
func WithActiveWorkers(withActive bool) Option {
	return func(o *options) {
		o.withActiveWorkers = withActive
	}
}

// WithFeature provides an option to specify a filter
func WithFeature(feature version.Feature) Option {
	return func(o *options) {
		o.withFeature = feature
	}
}

// WithDirectlyConnected provides an option to limit graph search to only directly connected workers
func WithDirectlyConnected(conn bool) Option {
	return func(o *options) {
		o.withDirectlyConnected = conn
	}
}

// WithWorkerPool provides a slice of worker ids.
func WithWorkerPool(workerIds []string) Option {
	return func(o *options) {
		o.withWorkerPool = workerIds
	}
}

// WithLocalStorageState provides an optional local storage state.
func WithLocalStorageState(state string) Option {
	return func(o *options) {
		o.withLocalStorageState = state
	}
}

// WithFilterWorkersByStorageBucketCredentialState receives a storage bucket
// credential id and filters to apply and calls
// FilterWorkersByStorageBucketCredentialState in supported repository
// functions.
func WithFilterWorkersByStorageBucketCredentialState(ci *StorageBucketCredentialInfo) Option {
	return func(o *options) {
		o.withFilterWorkersByStorageBucketCredentialState = ci
	}
}

// WithFilterWorkersByLocalStorageState controls whether
// FilterWorkersByLocalStorageState is called in supported repository functions.
func WithFilterWorkersByLocalStorageState(filter bool) Option {
	return func(o *options) {
		o.withFilterWorkersByLocalStorageState = filter
	}
}

// WithReaderWriter is used to share the same database reader
// and writer when executing sql within a transaction.
func WithReaderWriter(r db.Reader, w db.Writer) Option {
	return func(o *options) {
		o.WithReader = r
		o.WithWriter = w
	}
}

// WithRandomReader provides an option to specify a random reader.
func WithRandomReader(reader io.Reader) Option {
	return func(o *options) {
		o.withRandomReader = reader
	}
}
