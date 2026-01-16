// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package handlers

import (
	"context"
	"testing"

	pb "github.com/hashicorp/boundary/sdk/pbs/controller/protooptions"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMaskManager(t *testing.T) {
	mm, err := NewMaskManager(context.Background(), MaskDestination{&pb.TestProperlyNamedFields{}}, MaskSource{&pb.TestBase{}})
	require.NoError(t, err)
	assert.Equal(t, []string(nil), mm.Translate([]string{"doesnt_exist"}))
	assert.Equal(t, []string{"OtherFirstField"}, mm.Translate([]string{"first_field"}))
	assert.Equal(t, []string{"OtherFirstField"}, mm.Translate([]string{"first_field", "doesnt_exist"}))
	assert.Equal(t, []string(nil), mm.Translate([]string{"FiRsT_fIeLd"}))
	assert.Equal(t, []string{"other_second_field"}, mm.Translate([]string{"strangly_formatted_field"}))
	assert.Equal(t, []string{"other_second_field", "other_field_3"}, mm.Translate([]string{"strangly_formatted_field", "field3"}))

	// the passedThroughPrefix allows fields to be passed through unmodified
	assert.Equal(t, []string{"OtherFirstField", "attributes.doesnt_exist"}, mm.Translate([]string{"first_field", "attributes.doesnt_exist"}, "attributes."))
	// the passedThroughPrefix is ignored if the field already matches a mapped value
	assert.Equal(t, []string{"other_second_field", "other_field_3"}, mm.Translate([]string{"strangly_formatted_field", "field3"}, "strangely_"))
}

func TestMaskManager_Split(t *testing.T) {
	mm, err := NewMaskManager(context.Background(), MaskDestination{&pb.TestProperlyNamedFields{}}, MaskSource{&pb.TestBaseSplit1{}, &pb.TestBaseSplit2{}})
	require.NoError(t, err)
	assert.Equal(t, []string(nil), mm.Translate([]string{"doesnt_exist"}))
	assert.Equal(t, []string{"OtherFirstField"}, mm.Translate([]string{"first_field"}))
	assert.Equal(t, []string{"OtherFirstField"}, mm.Translate([]string{"first_field", "doesnt_exist"}))
	assert.Equal(t, []string(nil), mm.Translate([]string{"FiRsT_fIeLd"}))
	assert.Equal(t, []string{"other_second_field"}, mm.Translate([]string{"strangly_formatted_field"}))
	assert.Equal(t, []string{"other_second_field", "other_field_3"}, mm.Translate([]string{"strangly_formatted_field", "field3"}))
}

func TestMaskManager_errors(t *testing.T) {
	ctx := context.Background()
	_, err := NewMaskManager(ctx, MaskDestination{&pb.TestBase{}}, MaskSource{&pb.TestManyToOneMappings{}})
	assert.Error(t, err)
	_, err = NewMaskManager(ctx, MaskDestination{&pb.TestBase{}}, MaskSource{&pb.TestNameDoesntMap{}})
	assert.Error(t, err)
	_, err = NewMaskManager(ctx, MaskDestination{&pb.TestBase{}}, MaskSource{&pb.TestNotEnoughFields{}})
	assert.Error(t, err)
}
