// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0
// 	protoc        v3.12.3
// source: controller/api/resources/jobs/v1/job.proto

package jobs

import (
	proto "github.com/golang/protobuf/proto"
	timestamp "github.com/golang/protobuf/ptypes/timestamp"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

// Job contains all fields related to a Job resource
type Job struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The ID of the job
	// Output only.
	Id string `protobuf:"bytes,10,opt,name=id,proto3" json:"id,omitempty"`
	// The time the job entered pending state (e.g. creation)
	// Output only.
	PendingTime *timestamp.Timestamp `protobuf:"bytes,20,opt,name=pending_time,proto3" json:"pending_time,omitempty"`
	// The time the job entered active state (currently running)
	// Output only.
	ActiveTime *timestamp.Timestamp `protobuf:"bytes,30,opt,name=active_time,proto3" json:"active_time,omitempty"`
	// The time the job entered caneling state
	// Output only.
	CancelingTime *timestamp.Timestamp `protobuf:"bytes,40,opt,name=canceling_time,proto3" json:"canceling_time,omitempty"`
	// The time the job entered canceled state
	// Output only.
	CanceledTime *timestamp.Timestamp `protobuf:"bytes,50,opt,name=canceled_time,proto3" json:"canceled_time,omitempty"`
	// The time the job entered success state
	// Output only.
	CompleteTime *timestamp.Timestamp `protobuf:"bytes,60,opt,name=complete_time,proto3" json:"complete_time,omitempty"`
	// The type of job
	// Output only.
	Type string `protobuf:"bytes,70,opt,name=type,proto3" json:"type,omitempty"`
	// The current status of the job
	// Output only.
	Status string `protobuf:"bytes,80,opt,name=status,proto3" json:"status,omitempty"`
}

func (x *Job) Reset() {
	*x = Job{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_resources_jobs_v1_job_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Job) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Job) ProtoMessage() {}

func (x *Job) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_resources_jobs_v1_job_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Job.ProtoReflect.Descriptor instead.
func (*Job) Descriptor() ([]byte, []int) {
	return file_controller_api_resources_jobs_v1_job_proto_rawDescGZIP(), []int{0}
}

func (x *Job) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *Job) GetPendingTime() *timestamp.Timestamp {
	if x != nil {
		return x.PendingTime
	}
	return nil
}

func (x *Job) GetActiveTime() *timestamp.Timestamp {
	if x != nil {
		return x.ActiveTime
	}
	return nil
}

func (x *Job) GetCancelingTime() *timestamp.Timestamp {
	if x != nil {
		return x.CancelingTime
	}
	return nil
}

func (x *Job) GetCanceledTime() *timestamp.Timestamp {
	if x != nil {
		return x.CanceledTime
	}
	return nil
}

func (x *Job) GetCompleteTime() *timestamp.Timestamp {
	if x != nil {
		return x.CompleteTime
	}
	return nil
}

func (x *Job) GetType() string {
	if x != nil {
		return x.Type
	}
	return ""
}

func (x *Job) GetStatus() string {
	if x != nil {
		return x.Status
	}
	return ""
}

var File_controller_api_resources_jobs_v1_job_proto protoreflect.FileDescriptor

var file_controller_api_resources_jobs_v1_job_proto_rawDesc = []byte{
	0x0a, 0x2a, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x61, 0x70, 0x69,
	0x2f, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2f, 0x6a, 0x6f, 0x62, 0x73, 0x2f,
	0x76, 0x31, 0x2f, 0x6a, 0x6f, 0x62, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x20, 0x63, 0x6f,
	0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x72, 0x65, 0x73,
	0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2e, 0x6a, 0x6f, 0x62, 0x73, 0x2e, 0x76, 0x31, 0x1a, 0x1f,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f,
	0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22,
	0x87, 0x03, 0x0a, 0x03, 0x4a, 0x6f, 0x62, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x0a, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x3e, 0x0a, 0x0c, 0x70, 0x65, 0x6e, 0x64, 0x69,
	0x6e, 0x67, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x14, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e,
	0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x0c, 0x70, 0x65, 0x6e, 0x64, 0x69,
	0x6e, 0x67, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x12, 0x3c, 0x0a, 0x0b, 0x61, 0x63, 0x74, 0x69, 0x76,
	0x65, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x1e, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67,
	0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54,
	0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x0b, 0x61, 0x63, 0x74, 0x69, 0x76, 0x65,
	0x5f, 0x74, 0x69, 0x6d, 0x65, 0x12, 0x42, 0x0a, 0x0e, 0x63, 0x61, 0x6e, 0x63, 0x65, 0x6c, 0x69,
	0x6e, 0x67, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x28, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e,
	0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x0e, 0x63, 0x61, 0x6e, 0x63, 0x65,
	0x6c, 0x69, 0x6e, 0x67, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x12, 0x40, 0x0a, 0x0d, 0x63, 0x61, 0x6e,
	0x63, 0x65, 0x6c, 0x65, 0x64, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x32, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62,
	0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x0d, 0x63, 0x61,
	0x6e, 0x63, 0x65, 0x6c, 0x65, 0x64, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x12, 0x40, 0x0a, 0x0d, 0x63,
	0x6f, 0x6d, 0x70, 0x6c, 0x65, 0x74, 0x65, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x3c, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x0d,
	0x63, 0x6f, 0x6d, 0x70, 0x6c, 0x65, 0x74, 0x65, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x12, 0x12, 0x0a,
	0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x46, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x74, 0x79, 0x70,
	0x65, 0x12, 0x16, 0x0a, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x18, 0x50, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x42, 0x51, 0x5a, 0x4f, 0x67, 0x69, 0x74,
	0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x68, 0x61, 0x73, 0x68, 0x69, 0x63, 0x6f, 0x72,
	0x70, 0x2f, 0x77, 0x61, 0x74, 0x63, 0x68, 0x74, 0x6f, 0x77, 0x65, 0x72, 0x2f, 0x69, 0x6e, 0x74,
	0x65, 0x72, 0x6e, 0x61, 0x6c, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f,
	0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63,
	0x65, 0x73, 0x2f, 0x6a, 0x6f, 0x62, 0x73, 0x3b, 0x6a, 0x6f, 0x62, 0x73, 0x62, 0x06, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_controller_api_resources_jobs_v1_job_proto_rawDescOnce sync.Once
	file_controller_api_resources_jobs_v1_job_proto_rawDescData = file_controller_api_resources_jobs_v1_job_proto_rawDesc
)

func file_controller_api_resources_jobs_v1_job_proto_rawDescGZIP() []byte {
	file_controller_api_resources_jobs_v1_job_proto_rawDescOnce.Do(func() {
		file_controller_api_resources_jobs_v1_job_proto_rawDescData = protoimpl.X.CompressGZIP(file_controller_api_resources_jobs_v1_job_proto_rawDescData)
	})
	return file_controller_api_resources_jobs_v1_job_proto_rawDescData
}

var file_controller_api_resources_jobs_v1_job_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_controller_api_resources_jobs_v1_job_proto_goTypes = []interface{}{
	(*Job)(nil),                 // 0: controller.api.resources.jobs.v1.Job
	(*timestamp.Timestamp)(nil), // 1: google.protobuf.Timestamp
}
var file_controller_api_resources_jobs_v1_job_proto_depIdxs = []int32{
	1, // 0: controller.api.resources.jobs.v1.Job.pending_time:type_name -> google.protobuf.Timestamp
	1, // 1: controller.api.resources.jobs.v1.Job.active_time:type_name -> google.protobuf.Timestamp
	1, // 2: controller.api.resources.jobs.v1.Job.canceling_time:type_name -> google.protobuf.Timestamp
	1, // 3: controller.api.resources.jobs.v1.Job.canceled_time:type_name -> google.protobuf.Timestamp
	1, // 4: controller.api.resources.jobs.v1.Job.complete_time:type_name -> google.protobuf.Timestamp
	5, // [5:5] is the sub-list for method output_type
	5, // [5:5] is the sub-list for method input_type
	5, // [5:5] is the sub-list for extension type_name
	5, // [5:5] is the sub-list for extension extendee
	0, // [0:5] is the sub-list for field type_name
}

func init() { file_controller_api_resources_jobs_v1_job_proto_init() }
func file_controller_api_resources_jobs_v1_job_proto_init() {
	if File_controller_api_resources_jobs_v1_job_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_controller_api_resources_jobs_v1_job_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Job); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_controller_api_resources_jobs_v1_job_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_controller_api_resources_jobs_v1_job_proto_goTypes,
		DependencyIndexes: file_controller_api_resources_jobs_v1_job_proto_depIdxs,
		MessageInfos:      file_controller_api_resources_jobs_v1_job_proto_msgTypes,
	}.Build()
	File_controller_api_resources_jobs_v1_job_proto = out.File
	file_controller_api_resources_jobs_v1_job_proto_rawDesc = nil
	file_controller_api_resources_jobs_v1_job_proto_goTypes = nil
	file_controller_api_resources_jobs_v1_job_proto_depIdxs = nil
}
