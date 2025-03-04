// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        v5.29.0
// source: proto/enumeration.proto

package proto

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

// A universal envelope containing the actual domain event type
// and its serialized bytes.
type UniversalEnvelope struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	EventType string `protobuf:"bytes,1,opt,name=event_type,json=eventType,proto3" json:"event_type,omitempty"` // e.g. "TaskStarted", "TaskProgressed", etc.
	Payload   []byte `protobuf:"bytes,2,opt,name=payload,proto3" json:"payload,omitempty"`                      // serialized domain event data
}

func (x *UniversalEnvelope) Reset() {
	*x = UniversalEnvelope{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_enumeration_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UniversalEnvelope) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UniversalEnvelope) ProtoMessage() {}

func (x *UniversalEnvelope) ProtoReflect() protoreflect.Message {
	mi := &file_proto_enumeration_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UniversalEnvelope.ProtoReflect.Descriptor instead.
func (*UniversalEnvelope) Descriptor() ([]byte, []int) {
	return file_proto_enumeration_proto_rawDescGZIP(), []int{0}
}

func (x *UniversalEnvelope) GetEventType() string {
	if x != nil {
		return x.EventType
	}
	return ""
}

func (x *UniversalEnvelope) GetPayload() []byte {
	if x != nil {
		return x.Payload
	}
	return nil
}

var File_proto_enumeration_proto protoreflect.FileDescriptor

var file_proto_enumeration_proto_rawDesc = []byte{
	0x0a, 0x17, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x65, 0x6e, 0x75, 0x6d, 0x65, 0x72, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x07, 0x73, 0x63, 0x61, 0x6e, 0x6e,
	0x65, 0x72, 0x22, 0x4c, 0x0a, 0x11, 0x55, 0x6e, 0x69, 0x76, 0x65, 0x72, 0x73, 0x61, 0x6c, 0x45,
	0x6e, 0x76, 0x65, 0x6c, 0x6f, 0x70, 0x65, 0x12, 0x1d, 0x0a, 0x0a, 0x65, 0x76, 0x65, 0x6e, 0x74,
	0x5f, 0x74, 0x79, 0x70, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x65, 0x76, 0x65,
	0x6e, 0x74, 0x54, 0x79, 0x70, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61,
	0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x07, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64,
	0x42, 0x2e, 0x5a, 0x2c, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x61,
	0x68, 0x72, 0x61, 0x76, 0x2f, 0x67, 0x69, 0x74, 0x6c, 0x65, 0x61, 0x6b, 0x73, 0x2d, 0x61, 0x72,
	0x6d, 0x61, 0x64, 0x61, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x3b, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_proto_enumeration_proto_rawDescOnce sync.Once
	file_proto_enumeration_proto_rawDescData = file_proto_enumeration_proto_rawDesc
)

func file_proto_enumeration_proto_rawDescGZIP() []byte {
	file_proto_enumeration_proto_rawDescOnce.Do(func() {
		file_proto_enumeration_proto_rawDescData = protoimpl.X.CompressGZIP(file_proto_enumeration_proto_rawDescData)
	})
	return file_proto_enumeration_proto_rawDescData
}

var file_proto_enumeration_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_proto_enumeration_proto_goTypes = []interface{}{
	(*UniversalEnvelope)(nil), // 0: scanner.UniversalEnvelope
}
var file_proto_enumeration_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_proto_enumeration_proto_init() }
func file_proto_enumeration_proto_init() {
	if File_proto_enumeration_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_proto_enumeration_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UniversalEnvelope); i {
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
			RawDescriptor: file_proto_enumeration_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_proto_enumeration_proto_goTypes,
		DependencyIndexes: file_proto_enumeration_proto_depIdxs,
		MessageInfos:      file_proto_enumeration_proto_msgTypes,
	}.Build()
	File_proto_enumeration_proto = out.File
	file_proto_enumeration_proto_rawDesc = nil
	file_proto_enumeration_proto_goTypes = nil
	file_proto_enumeration_proto_depIdxs = nil
}
