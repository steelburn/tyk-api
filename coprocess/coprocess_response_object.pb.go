// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        v3.20.2
// source: coprocess_response_object.proto

package coprocess

import (
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

type ResponseObject struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	StatusCode int32             `protobuf:"varint,1,opt,name=status_code,json=statusCode,proto3" json:"status_code,omitempty"`
	RawBody    []byte            `protobuf:"bytes,2,opt,name=raw_body,json=rawBody,proto3" json:"raw_body,omitempty"`
	Body       string            `protobuf:"bytes,3,opt,name=body,proto3" json:"body,omitempty"`
	Headers    map[string]string `protobuf:"bytes,4,rep,name=headers,proto3" json:"headers,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (x *ResponseObject) Reset() {
	*x = ResponseObject{}
	if protoimpl.UnsafeEnabled {
		mi := &file_coprocess_response_object_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ResponseObject) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ResponseObject) ProtoMessage() {}

func (x *ResponseObject) ProtoReflect() protoreflect.Message {
	mi := &file_coprocess_response_object_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ResponseObject.ProtoReflect.Descriptor instead.
func (*ResponseObject) Descriptor() ([]byte, []int) {
	return file_coprocess_response_object_proto_rawDescGZIP(), []int{0}
}

func (x *ResponseObject) GetStatusCode() int32 {
	if x != nil {
		return x.StatusCode
	}
	return 0
}

func (x *ResponseObject) GetRawBody() []byte {
	if x != nil {
		return x.RawBody
	}
	return nil
}

func (x *ResponseObject) GetBody() string {
	if x != nil {
		return x.Body
	}
	return ""
}

func (x *ResponseObject) GetHeaders() map[string]string {
	if x != nil {
		return x.Headers
	}
	return nil
}

var File_coprocess_response_object_proto protoreflect.FileDescriptor

var file_coprocess_response_object_proto_rawDesc = []byte{
	0x0a, 0x1f, 0x63, 0x6f, 0x70, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x5f, 0x72, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x5f, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x12, 0x09, 0x63, 0x6f, 0x70, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x22, 0xde, 0x01, 0x0a,
	0x0e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x12,
	0x1f, 0x0a, 0x0b, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x5f, 0x63, 0x6f, 0x64, 0x65, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x05, 0x52, 0x0a, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x43, 0x6f, 0x64, 0x65,
	0x12, 0x19, 0x0a, 0x08, 0x72, 0x61, 0x77, 0x5f, 0x62, 0x6f, 0x64, 0x79, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x07, 0x72, 0x61, 0x77, 0x42, 0x6f, 0x64, 0x79, 0x12, 0x12, 0x0a, 0x04, 0x62,
	0x6f, 0x64, 0x79, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x62, 0x6f, 0x64, 0x79, 0x12,
	0x40, 0x0a, 0x07, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x73, 0x18, 0x04, 0x20, 0x03, 0x28, 0x0b,
	0x32, 0x26, 0x2e, 0x63, 0x6f, 0x70, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x2e, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x2e, 0x48, 0x65, 0x61, 0x64,
	0x65, 0x72, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x07, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72,
	0x73, 0x1a, 0x3a, 0x0a, 0x0c, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x73, 0x45, 0x6e, 0x74, 0x72,
	0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03,
	0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x42, 0x2a, 0x5a,
	0x28, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x54, 0x79, 0x6b, 0x54,
	0x65, 0x63, 0x68, 0x6e, 0x6f, 0x6c, 0x6f, 0x67, 0x69, 0x65, 0x73, 0x2f, 0x74, 0x79, 0x6b, 0x2f,
	0x63, 0x6f, 0x70, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x33,
}

var (
	file_coprocess_response_object_proto_rawDescOnce sync.Once
	file_coprocess_response_object_proto_rawDescData = file_coprocess_response_object_proto_rawDesc
)

func file_coprocess_response_object_proto_rawDescGZIP() []byte {
	file_coprocess_response_object_proto_rawDescOnce.Do(func() {
		file_coprocess_response_object_proto_rawDescData = protoimpl.X.CompressGZIP(file_coprocess_response_object_proto_rawDescData)
	})
	return file_coprocess_response_object_proto_rawDescData
}

var file_coprocess_response_object_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_coprocess_response_object_proto_goTypes = []interface{}{
	(*ResponseObject)(nil), // 0: coprocess.ResponseObject
	nil,                    // 1: coprocess.ResponseObject.HeadersEntry
}
var file_coprocess_response_object_proto_depIdxs = []int32{
	1, // 0: coprocess.ResponseObject.headers:type_name -> coprocess.ResponseObject.HeadersEntry
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_coprocess_response_object_proto_init() }
func file_coprocess_response_object_proto_init() {
	if File_coprocess_response_object_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_coprocess_response_object_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ResponseObject); i {
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
			RawDescriptor: file_coprocess_response_object_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_coprocess_response_object_proto_goTypes,
		DependencyIndexes: file_coprocess_response_object_proto_depIdxs,
		MessageInfos:      file_coprocess_response_object_proto_msgTypes,
	}.Build()
	File_coprocess_response_object_proto = out.File
	file_coprocess_response_object_proto_rawDesc = nil
	file_coprocess_response_object_proto_goTypes = nil
	file_coprocess_response_object_proto_depIdxs = nil
}
