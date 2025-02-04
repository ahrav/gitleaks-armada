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

type EnumerationTask struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	TaskId      string            `protobuf:"bytes,1,opt,name=task_id,json=taskId,proto3" json:"task_id,omitempty"`
	SourceType  SourceType        `protobuf:"varint,2,opt,name=source_type,json=sourceType,proto3,enum=shared.SourceType" json:"source_type,omitempty"`
	JobId       string            `protobuf:"bytes,3,opt,name=job_id,json=jobId,proto3" json:"job_id,omitempty"`
	SessionId   string            `protobuf:"bytes,4,opt,name=session_id,json=sessionId,proto3" json:"session_id,omitempty"`
	ResourceUri string            `protobuf:"bytes,5,opt,name=resource_uri,json=resourceUri,proto3" json:"resource_uri,omitempty"` // e.g., "git://github.com/org/repo"
	Metadata    map[string]string `protobuf:"bytes,6,rep,name=metadata,proto3" json:"metadata,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	Credentials *TaskCredentials  `protobuf:"bytes,7,opt,name=credentials,proto3" json:"credentials,omitempty"`
}

func (x *EnumerationTask) Reset() {
	*x = EnumerationTask{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_enumeration_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EnumerationTask) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EnumerationTask) ProtoMessage() {}

func (x *EnumerationTask) ProtoReflect() protoreflect.Message {
	mi := &file_proto_enumeration_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EnumerationTask.ProtoReflect.Descriptor instead.
func (*EnumerationTask) Descriptor() ([]byte, []int) {
	return file_proto_enumeration_proto_rawDescGZIP(), []int{1}
}

func (x *EnumerationTask) GetTaskId() string {
	if x != nil {
		return x.TaskId
	}
	return ""
}

func (x *EnumerationTask) GetSourceType() SourceType {
	if x != nil {
		return x.SourceType
	}
	return SourceType_SOURCE_TYPE_UNSPECIFIED
}

func (x *EnumerationTask) GetJobId() string {
	if x != nil {
		return x.JobId
	}
	return ""
}

func (x *EnumerationTask) GetSessionId() string {
	if x != nil {
		return x.SessionId
	}
	return ""
}

func (x *EnumerationTask) GetResourceUri() string {
	if x != nil {
		return x.ResourceUri
	}
	return ""
}

func (x *EnumerationTask) GetMetadata() map[string]string {
	if x != nil {
		return x.Metadata
	}
	return nil
}

func (x *EnumerationTask) GetCredentials() *TaskCredentials {
	if x != nil {
		return x.Credentials
	}
	return nil
}

type TaskCredentials struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Auth:
	//
	//	*TaskCredentials_Unauthenticated
	//	*TaskCredentials_Github
	//	*TaskCredentials_S3
	Auth isTaskCredentials_Auth `protobuf_oneof:"auth"`
}

func (x *TaskCredentials) Reset() {
	*x = TaskCredentials{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_enumeration_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TaskCredentials) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TaskCredentials) ProtoMessage() {}

func (x *TaskCredentials) ProtoReflect() protoreflect.Message {
	mi := &file_proto_enumeration_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TaskCredentials.ProtoReflect.Descriptor instead.
func (*TaskCredentials) Descriptor() ([]byte, []int) {
	return file_proto_enumeration_proto_rawDescGZIP(), []int{2}
}

func (m *TaskCredentials) GetAuth() isTaskCredentials_Auth {
	if m != nil {
		return m.Auth
	}
	return nil
}

func (x *TaskCredentials) GetUnauthenticated() *UnauthenticatedCredentials {
	if x, ok := x.GetAuth().(*TaskCredentials_Unauthenticated); ok {
		return x.Unauthenticated
	}
	return nil
}

func (x *TaskCredentials) GetGithub() *GitHubCredentials {
	if x, ok := x.GetAuth().(*TaskCredentials_Github); ok {
		return x.Github
	}
	return nil
}

func (x *TaskCredentials) GetS3() *S3Credentials {
	if x, ok := x.GetAuth().(*TaskCredentials_S3); ok {
		return x.S3
	}
	return nil
}

type isTaskCredentials_Auth interface {
	isTaskCredentials_Auth()
}

type TaskCredentials_Unauthenticated struct {
	Unauthenticated *UnauthenticatedCredentials `protobuf:"bytes,1,opt,name=unauthenticated,proto3,oneof"`
}

type TaskCredentials_Github struct {
	Github *GitHubCredentials `protobuf:"bytes,2,opt,name=github,proto3,oneof"`
}

type TaskCredentials_S3 struct {
	S3 *S3Credentials `protobuf:"bytes,3,opt,name=s3,proto3,oneof"`
}

func (*TaskCredentials_Unauthenticated) isTaskCredentials_Auth() {}

func (*TaskCredentials_Github) isTaskCredentials_Auth() {}

func (*TaskCredentials_S3) isTaskCredentials_Auth() {}

type UnauthenticatedCredentials struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *UnauthenticatedCredentials) Reset() {
	*x = UnauthenticatedCredentials{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_enumeration_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UnauthenticatedCredentials) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UnauthenticatedCredentials) ProtoMessage() {}

func (x *UnauthenticatedCredentials) ProtoReflect() protoreflect.Message {
	mi := &file_proto_enumeration_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UnauthenticatedCredentials.ProtoReflect.Descriptor instead.
func (*UnauthenticatedCredentials) Descriptor() ([]byte, []int) {
	return file_proto_enumeration_proto_rawDescGZIP(), []int{3}
}

type GitHubCredentials struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AuthToken string `protobuf:"bytes,1,opt,name=auth_token,json=authToken,proto3" json:"auth_token,omitempty"`
}

func (x *GitHubCredentials) Reset() {
	*x = GitHubCredentials{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_enumeration_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GitHubCredentials) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GitHubCredentials) ProtoMessage() {}

func (x *GitHubCredentials) ProtoReflect() protoreflect.Message {
	mi := &file_proto_enumeration_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GitHubCredentials.ProtoReflect.Descriptor instead.
func (*GitHubCredentials) Descriptor() ([]byte, []int) {
	return file_proto_enumeration_proto_rawDescGZIP(), []int{4}
}

func (x *GitHubCredentials) GetAuthToken() string {
	if x != nil {
		return x.AuthToken
	}
	return ""
}

type S3Credentials struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AccessKey    string `protobuf:"bytes,1,opt,name=access_key,json=accessKey,proto3" json:"access_key,omitempty"`
	SecretKey    string `protobuf:"bytes,2,opt,name=secret_key,json=secretKey,proto3" json:"secret_key,omitempty"`
	SessionToken string `protobuf:"bytes,3,opt,name=session_token,json=sessionToken,proto3" json:"session_token,omitempty"` // Optional for temporary credentials
}

func (x *S3Credentials) Reset() {
	*x = S3Credentials{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_enumeration_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *S3Credentials) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*S3Credentials) ProtoMessage() {}

func (x *S3Credentials) ProtoReflect() protoreflect.Message {
	mi := &file_proto_enumeration_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use S3Credentials.ProtoReflect.Descriptor instead.
func (*S3Credentials) Descriptor() ([]byte, []int) {
	return file_proto_enumeration_proto_rawDescGZIP(), []int{5}
}

func (x *S3Credentials) GetAccessKey() string {
	if x != nil {
		return x.AccessKey
	}
	return ""
}

func (x *S3Credentials) GetSecretKey() string {
	if x != nil {
		return x.SecretKey
	}
	return ""
}

func (x *S3Credentials) GetSessionToken() string {
	if x != nil {
		return x.SessionToken
	}
	return ""
}

var File_proto_enumeration_proto protoreflect.FileDescriptor

var file_proto_enumeration_proto_rawDesc = []byte{
	0x0a, 0x17, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x65, 0x6e, 0x75, 0x6d, 0x65, 0x72, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x07, 0x73, 0x63, 0x61, 0x6e, 0x6e,
	0x65, 0x72, 0x1a, 0x12, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x73, 0x68, 0x61, 0x72, 0x65, 0x64,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x4c, 0x0a, 0x11, 0x55, 0x6e, 0x69, 0x76, 0x65, 0x72,
	0x73, 0x61, 0x6c, 0x45, 0x6e, 0x76, 0x65, 0x6c, 0x6f, 0x70, 0x65, 0x12, 0x1d, 0x0a, 0x0a, 0x65,
	0x76, 0x65, 0x6e, 0x74, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x09, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x54, 0x79, 0x70, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x70, 0x61,
	0x79, 0x6c, 0x6f, 0x61, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x07, 0x70, 0x61, 0x79,
	0x6c, 0x6f, 0x61, 0x64, 0x22, 0xf5, 0x02, 0x0a, 0x0f, 0x45, 0x6e, 0x75, 0x6d, 0x65, 0x72, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x54, 0x61, 0x73, 0x6b, 0x12, 0x17, 0x0a, 0x07, 0x74, 0x61, 0x73, 0x6b,
	0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x74, 0x61, 0x73, 0x6b, 0x49,
	0x64, 0x12, 0x33, 0x0a, 0x0b, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x5f, 0x74, 0x79, 0x70, 0x65,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x12, 0x2e, 0x73, 0x68, 0x61, 0x72, 0x65, 0x64, 0x2e,
	0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x54, 0x79, 0x70, 0x65, 0x52, 0x0a, 0x73, 0x6f, 0x75, 0x72,
	0x63, 0x65, 0x54, 0x79, 0x70, 0x65, 0x12, 0x15, 0x0a, 0x06, 0x6a, 0x6f, 0x62, 0x5f, 0x69, 0x64,
	0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x6a, 0x6f, 0x62, 0x49, 0x64, 0x12, 0x1d, 0x0a,
	0x0a, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x69, 0x64, 0x18, 0x04, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x09, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x49, 0x64, 0x12, 0x21, 0x0a, 0x0c,
	0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x5f, 0x75, 0x72, 0x69, 0x18, 0x05, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x0b, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x55, 0x72, 0x69, 0x12,
	0x42, 0x0a, 0x08, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x18, 0x06, 0x20, 0x03, 0x28,
	0x0b, 0x32, 0x26, 0x2e, 0x73, 0x63, 0x61, 0x6e, 0x6e, 0x65, 0x72, 0x2e, 0x45, 0x6e, 0x75, 0x6d,
	0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x54, 0x61, 0x73, 0x6b, 0x2e, 0x4d, 0x65, 0x74, 0x61,
	0x64, 0x61, 0x74, 0x61, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x08, 0x6d, 0x65, 0x74, 0x61, 0x64,
	0x61, 0x74, 0x61, 0x12, 0x3a, 0x0a, 0x0b, 0x63, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61,
	0x6c, 0x73, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x18, 0x2e, 0x73, 0x63, 0x61, 0x6e, 0x6e,
	0x65, 0x72, 0x2e, 0x54, 0x61, 0x73, 0x6b, 0x43, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61,
	0x6c, 0x73, 0x52, 0x0b, 0x63, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73, 0x1a,
	0x3b, 0x0a, 0x0d, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x45, 0x6e, 0x74, 0x72, 0x79,
	0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b,
	0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x22, 0xca, 0x01, 0x0a,
	0x0f, 0x54, 0x61, 0x73, 0x6b, 0x43, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73,
	0x12, 0x4f, 0x0a, 0x0f, 0x75, 0x6e, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61,
	0x74, 0x65, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x23, 0x2e, 0x73, 0x63, 0x61, 0x6e,
	0x6e, 0x65, 0x72, 0x2e, 0x55, 0x6e, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61,
	0x74, 0x65, 0x64, 0x43, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73, 0x48, 0x00,
	0x52, 0x0f, 0x75, 0x6e, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x65,
	0x64, 0x12, 0x34, 0x0a, 0x06, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x1a, 0x2e, 0x73, 0x63, 0x61, 0x6e, 0x6e, 0x65, 0x72, 0x2e, 0x47, 0x69, 0x74, 0x48,
	0x75, 0x62, 0x43, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73, 0x48, 0x00, 0x52,
	0x06, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x12, 0x28, 0x0a, 0x02, 0x73, 0x33, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x16, 0x2e, 0x73, 0x63, 0x61, 0x6e, 0x6e, 0x65, 0x72, 0x2e, 0x53, 0x33,
	0x43, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73, 0x48, 0x00, 0x52, 0x02, 0x73,
	0x33, 0x42, 0x06, 0x0a, 0x04, 0x61, 0x75, 0x74, 0x68, 0x22, 0x1c, 0x0a, 0x1a, 0x55, 0x6e, 0x61,
	0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x65, 0x64, 0x43, 0x72, 0x65, 0x64,
	0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73, 0x22, 0x32, 0x0a, 0x11, 0x47, 0x69, 0x74, 0x48, 0x75,
	0x62, 0x43, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73, 0x12, 0x1d, 0x0a, 0x0a,
	0x61, 0x75, 0x74, 0x68, 0x5f, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x09, 0x61, 0x75, 0x74, 0x68, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x22, 0x72, 0x0a, 0x0d, 0x53,
	0x33, 0x43, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73, 0x12, 0x1d, 0x0a, 0x0a,
	0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x5f, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x09, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x4b, 0x65, 0x79, 0x12, 0x1d, 0x0a, 0x0a, 0x73,
	0x65, 0x63, 0x72, 0x65, 0x74, 0x5f, 0x6b, 0x65, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x09, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x4b, 0x65, 0x79, 0x12, 0x23, 0x0a, 0x0d, 0x73, 0x65,
	0x73, 0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x0c, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x42,
	0x2e, 0x5a, 0x2c, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x61, 0x68,
	0x72, 0x61, 0x76, 0x2f, 0x67, 0x69, 0x74, 0x6c, 0x65, 0x61, 0x6b, 0x73, 0x2d, 0x61, 0x72, 0x6d,
	0x61, 0x64, 0x61, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x3b, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62,
	0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
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

var file_proto_enumeration_proto_msgTypes = make([]protoimpl.MessageInfo, 7)
var file_proto_enumeration_proto_goTypes = []interface{}{
	(*UniversalEnvelope)(nil),          // 0: scanner.UniversalEnvelope
	(*EnumerationTask)(nil),            // 1: scanner.EnumerationTask
	(*TaskCredentials)(nil),            // 2: scanner.TaskCredentials
	(*UnauthenticatedCredentials)(nil), // 3: scanner.UnauthenticatedCredentials
	(*GitHubCredentials)(nil),          // 4: scanner.GitHubCredentials
	(*S3Credentials)(nil),              // 5: scanner.S3Credentials
	nil,                                // 6: scanner.EnumerationTask.MetadataEntry
	(SourceType)(0),                    // 7: shared.SourceType
}
var file_proto_enumeration_proto_depIdxs = []int32{
	7, // 0: scanner.EnumerationTask.source_type:type_name -> shared.SourceType
	6, // 1: scanner.EnumerationTask.metadata:type_name -> scanner.EnumerationTask.MetadataEntry
	2, // 2: scanner.EnumerationTask.credentials:type_name -> scanner.TaskCredentials
	3, // 3: scanner.TaskCredentials.unauthenticated:type_name -> scanner.UnauthenticatedCredentials
	4, // 4: scanner.TaskCredentials.github:type_name -> scanner.GitHubCredentials
	5, // 5: scanner.TaskCredentials.s3:type_name -> scanner.S3Credentials
	6, // [6:6] is the sub-list for method output_type
	6, // [6:6] is the sub-list for method input_type
	6, // [6:6] is the sub-list for extension type_name
	6, // [6:6] is the sub-list for extension extendee
	0, // [0:6] is the sub-list for field type_name
}

func init() { file_proto_enumeration_proto_init() }
func file_proto_enumeration_proto_init() {
	if File_proto_enumeration_proto != nil {
		return
	}
	file_proto_shared_proto_init()
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
		file_proto_enumeration_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*EnumerationTask); i {
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
		file_proto_enumeration_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TaskCredentials); i {
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
		file_proto_enumeration_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UnauthenticatedCredentials); i {
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
		file_proto_enumeration_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GitHubCredentials); i {
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
		file_proto_enumeration_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*S3Credentials); i {
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
	file_proto_enumeration_proto_msgTypes[2].OneofWrappers = []interface{}{
		(*TaskCredentials_Unauthenticated)(nil),
		(*TaskCredentials_Github)(nil),
		(*TaskCredentials_S3)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_proto_enumeration_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   7,
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
