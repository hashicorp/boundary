// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package event

import (
	"testing"

	"github.com/hashicorp/boundary/internal/gen/controller/servers"
	"github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	tassert "github.com/stretchr/testify/assert"
)

func Test_OnlyObservationTaggedFieldsPopulated(t *testing.T) {
	assert := tassert.New(t)

	input := &services.StatusRequest{
		Jobs: []*services.JobStatus{
			{Job: &services.Job{
				Type:    1,
				JobInfo: nil,
			}},
		},
		UpdateTags: false,
		WorkerStatus: &servers.ServerWorkerStatus{
			PublicId:    "testID",
			Name:        "w_1234567890",
			Description: "A default worker created in",
			Address:     "127.0.0.1:9202",
			Tags: []*servers.TagPair{
				{
					Key:   "type",
					Value: "dev",
				},
			},
			KeyId:            "ovary-valid-curler-scrambled-glutinous-alias-rework-debit",
			ReleaseVersion:   "Boundary v0.13.1",
			OperationalState: "active",
		},
	}

	filtered, err := filterProtoMessage(input, telemetryFilter)
	assert.NoError(err)

	output, ok := filtered.(*services.StatusRequest)
	assert.True(ok)

	// expected content
	assert.NotNil(output.WorkerStatus)
	assert.Equal(input.WorkerStatus.PublicId, output.WorkerStatus.PublicId)
	assert.Equal(input.WorkerStatus.ReleaseVersion, output.WorkerStatus.ReleaseVersion)
	assert.Equal(input.WorkerStatus.OperationalState, output.WorkerStatus.OperationalState)

	// non expected content
	assert.Zero(output.WorkerStatus.Name)
	assert.Zero(output.WorkerStatus.Address)
	assert.Zero(output.WorkerStatus.Description)
	assert.Zero(output.WorkerStatus.KeyId)
	assert.Len(output.WorkerStatus.Tags, 1)
	assert.Len(output.Jobs, 1)
}

func Test_AllFieldsPopulatedWithoutFilter(t *testing.T) {
	assert := tassert.New(t)
	input := &services.StatusRequest{
		Jobs: []*services.JobStatus{
			{Job: &services.Job{
				Type:    1,
				JobInfo: nil,
			}},
		},
		UpdateTags: false,
		WorkerStatus: &servers.ServerWorkerStatus{
			PublicId:    "testID",
			Name:        "w_1234567890",
			Description: "A default worker created in",
			Address:     "127.0.0.1:9202",
			Tags: []*servers.TagPair{
				{
					Key:   "type",
					Value: "dev",
				},
			},
			KeyId:            "ovary-valid-curler-scrambled-glutinous-alias-rework-debit",
			ReleaseVersion:   "Boundary v0.13.1",
			OperationalState: "active",
		},
	}

	filtered, err := filterProtoMessage(input, nil)
	assert.NoError(err)

	output, ok := filtered.(*services.StatusRequest)
	assert.True(ok)

	// expected content
	assert.Equal(input, output)
}

func Test_NilMessageWillError(t *testing.T) {
	assert := tassert.New(t)

	_, err := filterProtoMessage(nil, nil)
	assert.Error(err)
}
