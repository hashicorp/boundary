// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package event

import (
	"reflect"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

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
	assert.Len(output.WorkerStatus.Tags, 0)
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

func Test_scalarSliceFilterAllZeroVals(t *testing.T) {
	assert := tassert.New(t)
	type testType struct {
		NonObservableStrings []string
		ObservableInts       []int `eventstream:"observation" class:"public"`
	}
	data := &testType{
		NonObservableStrings: []string{"a", "b", "c"},
		ObservableInts:       []int{1, 2, 3, 4},
	}
	err := recurseStructureWithProtoFilter(reflect.ValueOf(data), telemetryFilter, false)
	assert.NoError(err)
	assert.Len(data.NonObservableStrings, 0)
	assert.Len(data.ObservableInts, 4)
}

func Test_mapFilter(t *testing.T) {
	assert := tassert.New(t)
	type testType struct {
		NonObservableMap map[string]int
		ObservableMap    map[string]int `eventstream:"observation" class:"public"`
	}
	data := &testType{
		NonObservableMap: map[string]int{
			"a": 1,
			"b": 2,
			"c": 3,
		},
		ObservableMap: map[string]int{
			"d": 4,
			"e": 5,
			"f": 6,
		},
	}
	err := recurseStructureWithProtoFilter(reflect.ValueOf(data), telemetryFilter, false)
	assert.NoError(err)
	assert.Len(data.NonObservableMap, 0)
	assert.Len(data.ObservableMap, 3)
	assert.Equal(data.ObservableMap, map[string]int{
		"d": 4,
		"e": 5,
		"f": 6,
	})
}

func Test_coreProtoTypes(t *testing.T) {
	assert := tassert.New(t)
	type testType struct {
		Timestamp        *timestamppb.Timestamp
		TimestampObs     *timestamppb.Timestamp `eventstream:"observation" class:"public"`
		WrappedString    *wrapperspb.StringValue
		WrappedStringObs *wrapperspb.StringValue `eventstream:"observation" class:"public"`
		Fieldmask        *fieldmaskpb.FieldMask
		FieldmaskObs     *fieldmaskpb.FieldMask `eventstream:"observation" class:"public"`
	}
	data := &testType{
		Timestamp: &timestamppb.Timestamp{
			Seconds: 1694589179,
			Nanos:   812910000,
		},
		TimestampObs: &timestamppb.Timestamp{
			Seconds: 1694589179,
			Nanos:   812910000,
		},
		WrappedString:    &wrapperspb.StringValue{Value: "[REDACTED]"},
		WrappedStringObs: &wrapperspb.StringValue{Value: "[REDACTED]"},
		Fieldmask: &fieldmaskpb.FieldMask{
			Paths: []string{"a", "b"},
		},
		FieldmaskObs: &fieldmaskpb.FieldMask{
			Paths: []string{"a", "b"},
		},
	}
	err := recurseStructureWithProtoFilter(reflect.ValueOf(data), telemetryFilter, false)
	assert.NoError(err)
	assert.Nil(data.WrappedString)
	assert.Nil(data.Timestamp)
	assert.Nil(data.Fieldmask)
	assert.NotNil(data.TimestampObs)
	assert.NotNil(data.WrappedStringObs)
	assert.NotNil(data.FieldmaskObs)
	assert.Equal(data.TimestampObs, &timestamppb.Timestamp{
		Seconds: 1694589179,
		Nanos:   812910000,
	})
	assert.Equal(data.WrappedStringObs, &wrapperspb.StringValue{Value: "[REDACTED]"})
	assert.Equal(data.FieldmaskObs, &fieldmaskpb.FieldMask{
		Paths: []string{"a", "b"},
	})
}

func Test_mapStructPBValues(t *testing.T) {
	assert := tassert.New(t)
	type testType struct {
		ListValueMap    map[string]*structpb.ListValue
		ListValueMapObs map[string]*structpb.ListValue `eventstream:"observation" class:"public"`
	}
	data := &testType{
		ListValueMap: map[string]*structpb.ListValue{
			"one": {Values: []*structpb.Value{
				structpb.NewStringValue("one"),
			}},
			"two": {Values: []*structpb.Value{
				structpb.NewStringValue("two"),
			}},
		},
		ListValueMapObs: map[string]*structpb.ListValue{
			"three": {Values: []*structpb.Value{
				structpb.NewStringValue("three"),
			}},
			"four": {Values: []*structpb.Value{
				structpb.NewStringValue("four"),
			}},
		},
	}
	err := recurseStructureWithProtoFilter(reflect.ValueOf(data), telemetryFilter, false)
	assert.NoError(err)
	assert.Len(data.ListValueMapObs, 2)
	assert.True(
		proto.Equal(
			data.ListValueMapObs["three"],
			&structpb.ListValue{
				Values: []*structpb.Value{
					structpb.NewStringValue("three"),
				},
			},
		),
	)
	assert.True(
		proto.Equal(
			data.ListValueMapObs["four"],
			&structpb.ListValue{
				Values: []*structpb.Value{
					structpb.NewStringValue("four"),
				},
			},
		),
	)
	assert.Len(data.ListValueMap, 0)
}

func Test_sliceStructPBValues(t *testing.T) {
	assert := tassert.New(t)
	type testType struct {
		ListValueSlice    []*structpb.ListValue
		ListValueSliceObs []*structpb.ListValue `eventstream:"observation" class:"public"`
		ListValueArray    [2]*structpb.ListValue
	}
	data := &testType{
		ListValueSlice: []*structpb.ListValue{
			{Values: []*structpb.Value{
				structpb.NewStringValue("one"),
			}},
			{Values: []*structpb.Value{
				structpb.NewStringValue("two"),
			}},
		},
		ListValueSliceObs: []*structpb.ListValue{
			{Values: []*structpb.Value{
				structpb.NewStringValue("three"),
			}},
			{Values: []*structpb.Value{
				structpb.NewStringValue("four"),
			}},
		},
		ListValueArray: [2]*structpb.ListValue{
			{Values: []*structpb.Value{
				structpb.NewStringValue("five"),
			}},
			{Values: []*structpb.Value{
				structpb.NewStringValue("six"),
			}},
		},
	}
	err := recurseStructureWithProtoFilter(reflect.ValueOf(data), telemetryFilter, false)
	assert.NoError(err)
	assert.Len(data.ListValueSliceObs, 2)
	assert.True(
		proto.Equal(
			data.ListValueSliceObs[0],
			&structpb.ListValue{
				Values: []*structpb.Value{
					structpb.NewStringValue("three"),
				},
			},
		),
	)
	assert.True(
		proto.Equal(
			data.ListValueSliceObs[1],
			&structpb.ListValue{
				Values: []*structpb.Value{
					structpb.NewStringValue("four"),
				},
			},
		),
	)
	assert.Len(data.ListValueSlice, 0)
	assert.Len(data.ListValueArray, 2)
	assert.Nil(data.ListValueArray[0])
	assert.Nil(data.ListValueArray[1])
}

func Test_onlyPublicTelemetryFields(t *testing.T) {
	assert := tassert.New(t)
	type testType struct {
		NonObservableString       string
		NonPublicObservableString string `eventstream:"observation"`
		PublicObservableString    string `eventstream:"observation" class:"public"`
		SecretObservableString    string `eventstream:"observation" class:"secret"`
	}
	data := &testType{
		NonObservableString:       "empty",
		NonPublicObservableString: "empty",
		PublicObservableString:    "observable",
		SecretObservableString:    "empty",
	}
	err := recurseStructureWithProtoFilter(reflect.ValueOf(data), telemetryFilter, false)
	assert.NoError(err)
	assert.Equal(&testType{
		PublicObservableString: "observable",
	}, data)
}
