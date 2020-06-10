package common

import (
	"testing"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/sdk/helper/base62"
	"github.com/hashicorp/watchtower/internal/db/db_test"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
)

func Test_intersection(t *testing.T) {
	type args struct {
		av []string
		bv []string
	}
	tests := []struct {
		name       string
		args       args
		want       []string
		want1      map[string]string
		want2      map[string]string
		wantErr    bool
		wantErrMsg string
	}{
		{
			name: "intersect",
			args: args{
				av: []string{"alice"},
				bv: []string{"alice", "bob"},
			},
			want: []string{"alice"},
			want1: map[string]string{
				"ALICE": "alice",
			},
			want2: map[string]string{
				"ALICE": "alice",
				"BOB":   "bob",
			},
		},
		{
			name: "intersect-2",
			args: args{
				av: []string{"alice", "bob", "jane", "doe"},
				bv: []string{"alice", "doe", "bert", "ernie", "bigbird"},
			},
			want: []string{"alice", "doe"},
			want1: map[string]string{
				"ALICE": "alice",
				"BOB":   "bob",
				"JANE":  "jane",
				"DOE":   "doe",
			},
			want2: map[string]string{
				"ALICE":   "alice",
				"DOE":     "doe",
				"BERT":    "bert",
				"ERNIE":   "ernie",
				"BIGBIRD": "bigbird",
			},
		},
		{
			name: "intersect-mixed-case",
			args: args{
				av: []string{"AlicE"},
				bv: []string{"alICe", "Bob"},
			},
			want: []string{"alice"},
			want1: map[string]string{
				"ALICE": "AlicE",
			},
			want2: map[string]string{
				"ALICE": "alICe",
				"BOB":   "Bob",
			},
		},
		{
			name: "no-intersect-mixed-case",
			args: args{
				av: []string{"AliCe", "BOb", "jaNe", "DOE"},
				bv: []string{"beRt", "ERnie", "bigBIRD"},
			},
			want: []string{},
			want1: map[string]string{
				"ALICE": "AliCe",
				"BOB":   "BOb",
				"JANE":  "jaNe",
				"DOE":   "DOE",
			},
			want2: map[string]string{
				"BERT":    "beRt",
				"ERNIE":   "ERnie",
				"BIGBIRD": "bigBIRD",
			},
		},
		{
			name: "no-intersect-1",
			args: args{
				av: []string{"alice", "bob", "jane", "doe"},
				bv: []string{"bert", "ernie", "bigbird"},
			},
			want: []string{},
			want1: map[string]string{
				"ALICE": "alice",
				"BOB":   "bob",
				"JANE":  "jane",
				"DOE":   "doe",
			},
			want2: map[string]string{
				"BERT":    "bert",
				"ERNIE":   "ernie",
				"BIGBIRD": "bigbird",
			},
		},
		{
			name: "empty-av",
			args: args{
				av: []string{},
				bv: []string{"bert", "ernie", "bigbird"},
			},
			want:  []string{},
			want1: map[string]string{},
			want2: map[string]string{
				"BERT":    "bert",
				"ERNIE":   "ernie",
				"BIGBIRD": "bigbird",
			},
		},
		{
			name: "empty-av-and-bv",
			args: args{
				av: []string{},
				bv: []string{},
			},
			want:  []string{},
			want1: map[string]string{},
			want2: map[string]string{},
		},
		{
			name: "nil-av",
			args: args{
				av: nil,
				bv: []string{"bert", "ernie", "bigbird"},
			},
			want:       nil,
			want1:      nil,
			want2:      nil,
			wantErr:    true,
			wantErrMsg: "av is missing: nil parameter",
		},
		{
			name: "nil-bv",
			args: args{
				av: []string{},
				bv: nil,
			},
			want:       nil,
			want1:      nil,
			want2:      nil,
			wantErr:    true,
			wantErrMsg: "bv is missing: nil parameter",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			got, got1, got2, err := Intersection(tt.args.av, tt.args.bv)
			if err == nil && tt.wantErr {
				assert.Error(err)
			}
			if tt.wantErr {
				assert.Error(err)
				assert.Equal(tt.wantErrMsg, err.Error())
			}
			assert.Equal(tt.want, got)
			assert.Equal(tt.want1, got1)
			assert.Equal(tt.want2, got2)
		})
	}
}

func TestUpdateFields(t *testing.T) {
	a := assert.New(t)
	id, err := uuid.GenerateUUID()
	a.NoError(err)

	type args struct {
		i              interface{}
		fieldMaskPaths []string
		setToNullPaths []string
	}
	tests := []struct {
		name       string
		args       args
		want       map[string]interface{}
		wantErr    bool
		wantErrMsg string
	}{
		{
			name: "missing interface",
			args: args{
				i:              nil,
				fieldMaskPaths: []string{},
				setToNullPaths: []string{},
			},
			want:       nil,
			wantErr:    true,
			wantErrMsg: "interface is missing: nil parameter",
		},
		{
			name: "missing fieldmasks",
			args: args{
				i:              testUser(t, id, id),
				fieldMaskPaths: nil,
				setToNullPaths: []string{},
			},
			want:       nil,
			wantErr:    true,
			wantErrMsg: "both fieldMaskPaths and setToNullPaths are zero len",
		},
		{
			name: "missing null fields",
			args: args{
				i:              testUser(t, id, id),
				fieldMaskPaths: []string{"Name"},
				setToNullPaths: nil,
			},
			want: map[string]interface{}{
				"Name": id,
			},
			wantErr: false,
		},
		{
			name: "all zero len",
			args: args{
				i:              testUser(t, id, id),
				fieldMaskPaths: []string{},
				setToNullPaths: nil,
			},
			wantErr:    true,
			wantErrMsg: "both fieldMaskPaths and setToNullPaths are zero len",
		},
		{
			name: "not found masks",
			args: args{
				i:              testUser(t, id, id),
				fieldMaskPaths: []string{"invalidFieldName"},
				setToNullPaths: []string{},
			},
			want:       nil,
			wantErr:    true,
			wantErrMsg: "field mask paths not found in resource: [invalidFieldName]",
		},
		{
			name: "not found null paths",
			args: args{
				i:              testUser(t, id, id),
				fieldMaskPaths: []string{"name"},
				setToNullPaths: []string{"invalidFieldName"},
			},
			want:       nil,
			wantErr:    true,
			wantErrMsg: "null paths not found in resource: [invalidFieldName]",
		},
		{
			name: "intersection",
			args: args{
				i:              testUser(t, id, id),
				fieldMaskPaths: []string{"name"},
				setToNullPaths: []string{"name"},
			},
			want:       nil,
			wantErr:    true,
			wantErrMsg: "fieldMashPaths and setToNullPaths cannot intersect",
		},
		{
			name: "valid",
			args: args{
				i:              testUser(t, id, id),
				fieldMaskPaths: []string{"name"},
				setToNullPaths: []string{"email"},
			},
			want: map[string]interface{}{
				"name":  id,
				"email": gorm.Expr("NULL"),
			},
			wantErr:    false,
			wantErrMsg: "",
		},
		{
			name: "valid-just-masks",
			args: args{
				i:              testUser(t, id, id),
				fieldMaskPaths: []string{"name", "email"},
				setToNullPaths: []string{},
			},
			want: map[string]interface{}{
				"name":  id,
				"email": id,
			},
			wantErr:    false,
			wantErrMsg: "",
		},
		{
			name: "valid-just-nulls",
			args: args{
				i:              testUser(t, id, id),
				fieldMaskPaths: []string{},
				setToNullPaths: []string{"name", "email"},
			},
			want: map[string]interface{}{
				"name":  gorm.Expr("NULL"),
				"email": gorm.Expr("NULL"),
			},
			wantErr:    false,
			wantErrMsg: "",
		},
		{
			name: "valid-not-embedded",
			args: args{
				i: db_test.StoreTestUser{
					PublicId: testPublicId(t),
					Name:     id,
					Email:    "",
				},
				fieldMaskPaths: []string{"name"},
				setToNullPaths: []string{"email"},
			},
			want: map[string]interface{}{
				"name":  id,
				"email": gorm.Expr("NULL"),
			},
			wantErr:    false,
			wantErrMsg: "",
		},
		{
			name: "valid-not-embedded-just-masks",
			args: args{
				i: db_test.StoreTestUser{
					PublicId: testPublicId(t),
					Name:     id,
					Email:    "",
				},
				fieldMaskPaths: []string{"name"},
				setToNullPaths: nil,
			},
			want: map[string]interface{}{
				"name": id,
			},
			wantErr:    false,
			wantErrMsg: "",
		},
		{
			name: "valid-not-embedded-just-nulls",
			args: args{
				i: db_test.StoreTestUser{
					PublicId: testPublicId(t),
					Name:     id,
					Email:    "",
				},
				fieldMaskPaths: nil,
				setToNullPaths: []string{"email"},
			},
			want: map[string]interface{}{
				"email": gorm.Expr("NULL"),
			},
			wantErr:    false,
			wantErrMsg: "",
		},
		{
			name: "not found null paths - not embedded",
			args: args{
				i: db_test.StoreTestUser{
					PublicId: testPublicId(t),
					Name:     id,
					Email:    "",
				},
				fieldMaskPaths: []string{"name"},
				setToNullPaths: []string{"invalidFieldName"},
			},
			want:       nil,
			wantErr:    true,
			wantErrMsg: "null paths not found in resource: [invalidFieldName]",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			got, err := UpdateFields(tt.args.i, tt.args.fieldMaskPaths, tt.args.setToNullPaths)
			if err == nil && tt.wantErr {
				assert.Error(err)
			}
			if tt.wantErr {
				assert.Error(err)
				assert.Equal(tt.wantErrMsg, err.Error())
			}
			assert.Equal(tt.want, got)
		})
	}
}

func testUser(t *testing.T, name, email string) *db_test.TestUser {
	t.Helper()
	return &db_test.TestUser{
		StoreTestUser: &db_test.StoreTestUser{
			PublicId: testPublicId(t),
			Name:     name,
			Email:    email,
		},
	}
}

func testPublicId(t *testing.T) string {
	t.Helper()
	publicId, err := base62.Random(20)
	assert.NoError(t, err)
	return publicId
}
