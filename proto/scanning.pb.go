// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        v5.29.0
// source: proto/scanning.proto

package proto

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	structpb "google.golang.org/protobuf/types/known/structpb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type ScanJobStatus int32

const (
	ScanJobStatus_SCAN_JOB_STATUS_UNSPECIFIED ScanJobStatus = 0
	ScanJobStatus_SCAN_JOB_STATUS_QUEUED      ScanJobStatus = 1
	ScanJobStatus_SCAN_JOB_STATUS_RUNNING     ScanJobStatus = 2
	ScanJobStatus_SCAN_JOB_STATUS_COMPLETED   ScanJobStatus = 3
	ScanJobStatus_SCAN_JOB_STATUS_FAILED      ScanJobStatus = 4
)

// Enum value maps for ScanJobStatus.
var (
	ScanJobStatus_name = map[int32]string{
		0: "SCAN_JOB_STATUS_UNSPECIFIED",
		1: "SCAN_JOB_STATUS_QUEUED",
		2: "SCAN_JOB_STATUS_RUNNING",
		3: "SCAN_JOB_STATUS_COMPLETED",
		4: "SCAN_JOB_STATUS_FAILED",
	}
	ScanJobStatus_value = map[string]int32{
		"SCAN_JOB_STATUS_UNSPECIFIED": 0,
		"SCAN_JOB_STATUS_QUEUED":      1,
		"SCAN_JOB_STATUS_RUNNING":     2,
		"SCAN_JOB_STATUS_COMPLETED":   3,
		"SCAN_JOB_STATUS_FAILED":      4,
	}
)

func (x ScanJobStatus) Enum() *ScanJobStatus {
	p := new(ScanJobStatus)
	*p = x
	return p
}

func (x ScanJobStatus) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (ScanJobStatus) Descriptor() protoreflect.EnumDescriptor {
	return file_proto_scanning_proto_enumTypes[0].Descriptor()
}

func (ScanJobStatus) Type() protoreflect.EnumType {
	return &file_proto_scanning_proto_enumTypes[0]
}

func (x ScanJobStatus) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use ScanJobStatus.Descriptor instead.
func (ScanJobStatus) EnumDescriptor() ([]byte, []int) {
	return file_proto_scanning_proto_rawDescGZIP(), []int{0}
}

type TaskStatus int32

const (
	TaskStatus_TASK_STATUS_UNSPECIFIED TaskStatus = 0
	TaskStatus_TASK_STATUS_IN_PROGRESS TaskStatus = 1
	TaskStatus_TASK_STATUS_COMPLETED   TaskStatus = 2
	TaskStatus_TASK_STATUS_FAILED      TaskStatus = 3
)

// Enum value maps for TaskStatus.
var (
	TaskStatus_name = map[int32]string{
		0: "TASK_STATUS_UNSPECIFIED",
		1: "TASK_STATUS_IN_PROGRESS",
		2: "TASK_STATUS_COMPLETED",
		3: "TASK_STATUS_FAILED",
	}
	TaskStatus_value = map[string]int32{
		"TASK_STATUS_UNSPECIFIED": 0,
		"TASK_STATUS_IN_PROGRESS": 1,
		"TASK_STATUS_COMPLETED":   2,
		"TASK_STATUS_FAILED":      3,
	}
)

func (x TaskStatus) Enum() *TaskStatus {
	p := new(TaskStatus)
	*p = x
	return p
}

func (x TaskStatus) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (TaskStatus) Descriptor() protoreflect.EnumDescriptor {
	return file_proto_scanning_proto_enumTypes[1].Descriptor()
}

func (TaskStatus) Type() protoreflect.EnumType {
	return &file_proto_scanning_proto_enumTypes[1]
}

func (x TaskStatus) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use TaskStatus.Descriptor instead.
func (TaskStatus) EnumDescriptor() ([]byte, []int) {
	return file_proto_scanning_proto_rawDescGZIP(), []int{1}
}

// The final outcome of a scan, containing all discovered findings, status, etc.
type ScanResult struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Ties back to the ScanTask this result belongs to.
	TaskId string `protobuf:"bytes,1,opt,name=task_id,json=taskId,proto3" json:"task_id,omitempty"`
	// All secrets or matches found during this scan.
	Findings []*Finding `protobuf:"bytes,2,rep,name=findings,proto3" json:"findings,omitempty"`
	// Status of this job, matching your DB enum.
	Status ScanJobStatus `protobuf:"varint,3,opt,name=status,proto3,enum=scanner.ScanJobStatus" json:"status,omitempty"`
	// If status == SCAN_JOB_STATUS_FAILED, short error info here.
	Error string `protobuf:"bytes,4,opt,name=error,proto3" json:"error,omitempty"`
}

func (x *ScanResult) Reset() {
	*x = ScanResult{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_scanning_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ScanResult) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ScanResult) ProtoMessage() {}

func (x *ScanResult) ProtoReflect() protoreflect.Message {
	mi := &file_proto_scanning_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ScanResult.ProtoReflect.Descriptor instead.
func (*ScanResult) Descriptor() ([]byte, []int) {
	return file_proto_scanning_proto_rawDescGZIP(), []int{0}
}

func (x *ScanResult) GetTaskId() string {
	if x != nil {
		return x.TaskId
	}
	return ""
}

func (x *ScanResult) GetFindings() []*Finding {
	if x != nil {
		return x.Findings
	}
	return nil
}

func (x *ScanResult) GetStatus() ScanJobStatus {
	if x != nil {
		return x.Status
	}
	return ScanJobStatus_SCAN_JOB_STATUS_UNSPECIFIED
}

func (x *ScanResult) GetError() string {
	if x != nil {
		return x.Error
	}
	return ""
}

// A single discovered secret or match, typically stored in your DB 'findings'
// table.
type Finding struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// A unique key for deduplication (e.g., hash of path + secret).
	Fingerprint string `protobuf:"bytes,1,opt,name=fingerprint,proto3" json:"fingerprint,omitempty"`
	// The path or location of the found secret (universal).
	FilePath string `protobuf:"bytes,2,opt,name=file_path,json=filePath,proto3" json:"file_path,omitempty"`
	// Line number if relevant (e.g., scanning code).
	LineNumber int32 `protobuf:"varint,3,opt,name=line_number,json=lineNumber,proto3" json:"line_number,omitempty"`
	// Entire line of text, if captured. (Optional but convenient.)
	Line string `protobuf:"bytes,4,opt,name=line,proto3" json:"line,omitempty"`
	// The actual match that was found.
	Match string `protobuf:"bytes,5,opt,name=match,proto3" json:"match,omitempty"`
	// The author's email address.
	AuthorEmail string `protobuf:"bytes,6,opt,name=author_email,json=authorEmail,proto3" json:"author_email,omitempty"`
	// For ephemeral or extended data: commit hash, message, etc.
	RawFinding *structpb.Struct `protobuf:"bytes,7,opt,name=raw_finding,json=rawFinding,proto3" json:"raw_finding,omitempty"`
}

func (x *Finding) Reset() {
	*x = Finding{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_scanning_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Finding) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Finding) ProtoMessage() {}

func (x *Finding) ProtoReflect() protoreflect.Message {
	mi := &file_proto_scanning_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Finding.ProtoReflect.Descriptor instead.
func (*Finding) Descriptor() ([]byte, []int) {
	return file_proto_scanning_proto_rawDescGZIP(), []int{1}
}

func (x *Finding) GetFingerprint() string {
	if x != nil {
		return x.Fingerprint
	}
	return ""
}

func (x *Finding) GetFilePath() string {
	if x != nil {
		return x.FilePath
	}
	return ""
}

func (x *Finding) GetLineNumber() int32 {
	if x != nil {
		return x.LineNumber
	}
	return 0
}

func (x *Finding) GetLine() string {
	if x != nil {
		return x.Line
	}
	return ""
}

func (x *Finding) GetMatch() string {
	if x != nil {
		return x.Match
	}
	return ""
}

func (x *Finding) GetAuthorEmail() string {
	if x != nil {
		return x.AuthorEmail
	}
	return ""
}

func (x *Finding) GetRawFinding() *structpb.Struct {
	if x != nil {
		return x.RawFinding
	}
	return nil
}

type TaskStartedEvent struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	JobId     string `protobuf:"bytes,1,opt,name=job_id,json=jobId,proto3" json:"job_id,omitempty"`
	TaskId    string `protobuf:"bytes,2,opt,name=task_id,json=taskId,proto3" json:"task_id,omitempty"`
	Timestamp int64  `protobuf:"varint,3,opt,name=timestamp,proto3" json:"timestamp,omitempty"` // Unix timestamp in nanoseconds
}

func (x *TaskStartedEvent) Reset() {
	*x = TaskStartedEvent{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_scanning_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TaskStartedEvent) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TaskStartedEvent) ProtoMessage() {}

func (x *TaskStartedEvent) ProtoReflect() protoreflect.Message {
	mi := &file_proto_scanning_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TaskStartedEvent.ProtoReflect.Descriptor instead.
func (*TaskStartedEvent) Descriptor() ([]byte, []int) {
	return file_proto_scanning_proto_rawDescGZIP(), []int{2}
}

func (x *TaskStartedEvent) GetJobId() string {
	if x != nil {
		return x.JobId
	}
	return ""
}

func (x *TaskStartedEvent) GetTaskId() string {
	if x != nil {
		return x.TaskId
	}
	return ""
}

func (x *TaskStartedEvent) GetTimestamp() int64 {
	if x != nil {
		return x.Timestamp
	}
	return 0
}

type TaskProgressedEvent struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	TaskId          string      `protobuf:"bytes,1,opt,name=task_id,json=taskId,proto3" json:"task_id,omitempty"`
	SequenceNum     int64       `protobuf:"varint,2,opt,name=sequence_num,json=sequenceNum,proto3" json:"sequence_num,omitempty"`
	Timestamp       int64       `protobuf:"varint,3,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
	ItemsProcessed  int64       `protobuf:"varint,4,opt,name=items_processed,json=itemsProcessed,proto3" json:"items_processed,omitempty"`
	ErrorCount      int32       `protobuf:"varint,5,opt,name=error_count,json=errorCount,proto3" json:"error_count,omitempty"`
	Message         string      `protobuf:"bytes,6,opt,name=message,proto3" json:"message,omitempty"`
	ProgressDetails []byte      `protobuf:"bytes,7,opt,name=progress_details,json=progressDetails,proto3" json:"progress_details,omitempty"`
	Checkpoint      *Checkpoint `protobuf:"bytes,8,opt,name=checkpoint,proto3" json:"checkpoint,omitempty"`
}

func (x *TaskProgressedEvent) Reset() {
	*x = TaskProgressedEvent{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_scanning_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TaskProgressedEvent) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TaskProgressedEvent) ProtoMessage() {}

func (x *TaskProgressedEvent) ProtoReflect() protoreflect.Message {
	mi := &file_proto_scanning_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TaskProgressedEvent.ProtoReflect.Descriptor instead.
func (*TaskProgressedEvent) Descriptor() ([]byte, []int) {
	return file_proto_scanning_proto_rawDescGZIP(), []int{3}
}

func (x *TaskProgressedEvent) GetTaskId() string {
	if x != nil {
		return x.TaskId
	}
	return ""
}

func (x *TaskProgressedEvent) GetSequenceNum() int64 {
	if x != nil {
		return x.SequenceNum
	}
	return 0
}

func (x *TaskProgressedEvent) GetTimestamp() int64 {
	if x != nil {
		return x.Timestamp
	}
	return 0
}

func (x *TaskProgressedEvent) GetItemsProcessed() int64 {
	if x != nil {
		return x.ItemsProcessed
	}
	return 0
}

func (x *TaskProgressedEvent) GetErrorCount() int32 {
	if x != nil {
		return x.ErrorCount
	}
	return 0
}

func (x *TaskProgressedEvent) GetMessage() string {
	if x != nil {
		return x.Message
	}
	return ""
}

func (x *TaskProgressedEvent) GetProgressDetails() []byte {
	if x != nil {
		return x.ProgressDetails
	}
	return nil
}

func (x *TaskProgressedEvent) GetCheckpoint() *Checkpoint {
	if x != nil {
		return x.Checkpoint
	}
	return nil
}

type Checkpoint struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	TaskId      string            `protobuf:"bytes,1,opt,name=task_id,json=taskId,proto3" json:"task_id,omitempty"`
	Timestamp   int64             `protobuf:"varint,2,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
	ResumeToken []byte            `protobuf:"bytes,3,opt,name=resume_token,json=resumeToken,proto3" json:"resume_token,omitempty"`
	Metadata    map[string]string `protobuf:"bytes,4,rep,name=metadata,proto3" json:"metadata,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (x *Checkpoint) Reset() {
	*x = Checkpoint{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_scanning_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Checkpoint) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Checkpoint) ProtoMessage() {}

func (x *Checkpoint) ProtoReflect() protoreflect.Message {
	mi := &file_proto_scanning_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Checkpoint.ProtoReflect.Descriptor instead.
func (*Checkpoint) Descriptor() ([]byte, []int) {
	return file_proto_scanning_proto_rawDescGZIP(), []int{4}
}

func (x *Checkpoint) GetTaskId() string {
	if x != nil {
		return x.TaskId
	}
	return ""
}

func (x *Checkpoint) GetTimestamp() int64 {
	if x != nil {
		return x.Timestamp
	}
	return 0
}

func (x *Checkpoint) GetResumeToken() []byte {
	if x != nil {
		return x.ResumeToken
	}
	return nil
}

func (x *Checkpoint) GetMetadata() map[string]string {
	if x != nil {
		return x.Metadata
	}
	return nil
}

type TaskCompletedEvent struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	JobId     string `protobuf:"bytes,1,opt,name=job_id,json=jobId,proto3" json:"job_id,omitempty"`
	TaskId    string `protobuf:"bytes,2,opt,name=task_id,json=taskId,proto3" json:"task_id,omitempty"`
	Timestamp int64  `protobuf:"varint,3,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
}

func (x *TaskCompletedEvent) Reset() {
	*x = TaskCompletedEvent{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_scanning_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TaskCompletedEvent) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TaskCompletedEvent) ProtoMessage() {}

func (x *TaskCompletedEvent) ProtoReflect() protoreflect.Message {
	mi := &file_proto_scanning_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TaskCompletedEvent.ProtoReflect.Descriptor instead.
func (*TaskCompletedEvent) Descriptor() ([]byte, []int) {
	return file_proto_scanning_proto_rawDescGZIP(), []int{5}
}

func (x *TaskCompletedEvent) GetJobId() string {
	if x != nil {
		return x.JobId
	}
	return ""
}

func (x *TaskCompletedEvent) GetTaskId() string {
	if x != nil {
		return x.TaskId
	}
	return ""
}

func (x *TaskCompletedEvent) GetTimestamp() int64 {
	if x != nil {
		return x.Timestamp
	}
	return 0
}

type TaskFailedEvent struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	JobId     string `protobuf:"bytes,1,opt,name=job_id,json=jobId,proto3" json:"job_id,omitempty"`
	TaskId    string `protobuf:"bytes,2,opt,name=task_id,json=taskId,proto3" json:"task_id,omitempty"`
	Timestamp int64  `protobuf:"varint,3,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
	Reason    string `protobuf:"bytes,4,opt,name=reason,proto3" json:"reason,omitempty"`
}

func (x *TaskFailedEvent) Reset() {
	*x = TaskFailedEvent{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_scanning_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TaskFailedEvent) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TaskFailedEvent) ProtoMessage() {}

func (x *TaskFailedEvent) ProtoReflect() protoreflect.Message {
	mi := &file_proto_scanning_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TaskFailedEvent.ProtoReflect.Descriptor instead.
func (*TaskFailedEvent) Descriptor() ([]byte, []int) {
	return file_proto_scanning_proto_rawDescGZIP(), []int{6}
}

func (x *TaskFailedEvent) GetJobId() string {
	if x != nil {
		return x.JobId
	}
	return ""
}

func (x *TaskFailedEvent) GetTaskId() string {
	if x != nil {
		return x.TaskId
	}
	return ""
}

func (x *TaskFailedEvent) GetTimestamp() int64 {
	if x != nil {
		return x.Timestamp
	}
	return 0
}

func (x *TaskFailedEvent) GetReason() string {
	if x != nil {
		return x.Reason
	}
	return ""
}

type TaskHeartbeatEvent struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	TaskId    string `protobuf:"bytes,1,opt,name=task_id,json=taskId,proto3" json:"task_id,omitempty"`
	Timestamp int64  `protobuf:"varint,2,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
}

func (x *TaskHeartbeatEvent) Reset() {
	*x = TaskHeartbeatEvent{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_scanning_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TaskHeartbeatEvent) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TaskHeartbeatEvent) ProtoMessage() {}

func (x *TaskHeartbeatEvent) ProtoReflect() protoreflect.Message {
	mi := &file_proto_scanning_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TaskHeartbeatEvent.ProtoReflect.Descriptor instead.
func (*TaskHeartbeatEvent) Descriptor() ([]byte, []int) {
	return file_proto_scanning_proto_rawDescGZIP(), []int{7}
}

func (x *TaskHeartbeatEvent) GetTaskId() string {
	if x != nil {
		return x.TaskId
	}
	return ""
}

func (x *TaskHeartbeatEvent) GetTimestamp() int64 {
	if x != nil {
		return x.Timestamp
	}
	return 0
}

type TaskResumeEvent struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	JobId       string      `protobuf:"bytes,1,opt,name=job_id,json=jobId,proto3" json:"job_id,omitempty"`
	TaskId      string      `protobuf:"bytes,2,opt,name=task_id,json=taskId,proto3" json:"task_id,omitempty"`
	Timestamp   int64       `protobuf:"varint,3,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
	ResourceUri string      `protobuf:"bytes,4,opt,name=resource_uri,json=resourceUri,proto3" json:"resource_uri,omitempty"`
	SequenceNum int64       `protobuf:"varint,5,opt,name=sequence_num,json=sequenceNum,proto3" json:"sequence_num,omitempty"`
	Checkpoint  *Checkpoint `protobuf:"bytes,6,opt,name=checkpoint,proto3" json:"checkpoint,omitempty"`
}

func (x *TaskResumeEvent) Reset() {
	*x = TaskResumeEvent{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_scanning_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TaskResumeEvent) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TaskResumeEvent) ProtoMessage() {}

func (x *TaskResumeEvent) ProtoReflect() protoreflect.Message {
	mi := &file_proto_scanning_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TaskResumeEvent.ProtoReflect.Descriptor instead.
func (*TaskResumeEvent) Descriptor() ([]byte, []int) {
	return file_proto_scanning_proto_rawDescGZIP(), []int{8}
}

func (x *TaskResumeEvent) GetJobId() string {
	if x != nil {
		return x.JobId
	}
	return ""
}

func (x *TaskResumeEvent) GetTaskId() string {
	if x != nil {
		return x.TaskId
	}
	return ""
}

func (x *TaskResumeEvent) GetTimestamp() int64 {
	if x != nil {
		return x.Timestamp
	}
	return 0
}

func (x *TaskResumeEvent) GetResourceUri() string {
	if x != nil {
		return x.ResourceUri
	}
	return ""
}

func (x *TaskResumeEvent) GetSequenceNum() int64 {
	if x != nil {
		return x.SequenceNum
	}
	return 0
}

func (x *TaskResumeEvent) GetCheckpoint() *Checkpoint {
	if x != nil {
		return x.Checkpoint
	}
	return nil
}

var File_proto_scanning_proto protoreflect.FileDescriptor

var file_proto_scanning_proto_rawDesc = []byte{
	0x0a, 0x14, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x73, 0x63, 0x61, 0x6e, 0x6e, 0x69, 0x6e, 0x67,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x07, 0x73, 0x63, 0x61, 0x6e, 0x6e, 0x65, 0x72, 0x1a,
	0x1c, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2f, 0x73, 0x74, 0x72, 0x75, 0x63, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x99, 0x01,
	0x0a, 0x0a, 0x53, 0x63, 0x61, 0x6e, 0x52, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x12, 0x17, 0x0a, 0x07,
	0x74, 0x61, 0x73, 0x6b, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x74,
	0x61, 0x73, 0x6b, 0x49, 0x64, 0x12, 0x2c, 0x0a, 0x08, 0x66, 0x69, 0x6e, 0x64, 0x69, 0x6e, 0x67,
	0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x10, 0x2e, 0x73, 0x63, 0x61, 0x6e, 0x6e, 0x65,
	0x72, 0x2e, 0x46, 0x69, 0x6e, 0x64, 0x69, 0x6e, 0x67, 0x52, 0x08, 0x66, 0x69, 0x6e, 0x64, 0x69,
	0x6e, 0x67, 0x73, 0x12, 0x2e, 0x0a, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x0e, 0x32, 0x16, 0x2e, 0x73, 0x63, 0x61, 0x6e, 0x6e, 0x65, 0x72, 0x2e, 0x53, 0x63,
	0x61, 0x6e, 0x4a, 0x6f, 0x62, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x52, 0x06, 0x73, 0x74, 0x61,
	0x74, 0x75, 0x73, 0x12, 0x14, 0x0a, 0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x18, 0x04, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x22, 0xf0, 0x01, 0x0a, 0x07, 0x46, 0x69,
	0x6e, 0x64, 0x69, 0x6e, 0x67, 0x12, 0x20, 0x0a, 0x0b, 0x66, 0x69, 0x6e, 0x67, 0x65, 0x72, 0x70,
	0x72, 0x69, 0x6e, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x66, 0x69, 0x6e, 0x67,
	0x65, 0x72, 0x70, 0x72, 0x69, 0x6e, 0x74, 0x12, 0x1b, 0x0a, 0x09, 0x66, 0x69, 0x6c, 0x65, 0x5f,
	0x70, 0x61, 0x74, 0x68, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x66, 0x69, 0x6c, 0x65,
	0x50, 0x61, 0x74, 0x68, 0x12, 0x1f, 0x0a, 0x0b, 0x6c, 0x69, 0x6e, 0x65, 0x5f, 0x6e, 0x75, 0x6d,
	0x62, 0x65, 0x72, 0x18, 0x03, 0x20, 0x01, 0x28, 0x05, 0x52, 0x0a, 0x6c, 0x69, 0x6e, 0x65, 0x4e,
	0x75, 0x6d, 0x62, 0x65, 0x72, 0x12, 0x12, 0x0a, 0x04, 0x6c, 0x69, 0x6e, 0x65, 0x18, 0x04, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x04, 0x6c, 0x69, 0x6e, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x6d, 0x61, 0x74,
	0x63, 0x68, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x12,
	0x21, 0x0a, 0x0c, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x5f, 0x65, 0x6d, 0x61, 0x69, 0x6c, 0x18,
	0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x45, 0x6d, 0x61,
	0x69, 0x6c, 0x12, 0x38, 0x0a, 0x0b, 0x72, 0x61, 0x77, 0x5f, 0x66, 0x69, 0x6e, 0x64, 0x69, 0x6e,
	0x67, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x17, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x53, 0x74, 0x72, 0x75, 0x63, 0x74,
	0x52, 0x0a, 0x72, 0x61, 0x77, 0x46, 0x69, 0x6e, 0x64, 0x69, 0x6e, 0x67, 0x22, 0x60, 0x0a, 0x10,
	0x54, 0x61, 0x73, 0x6b, 0x53, 0x74, 0x61, 0x72, 0x74, 0x65, 0x64, 0x45, 0x76, 0x65, 0x6e, 0x74,
	0x12, 0x15, 0x0a, 0x06, 0x6a, 0x6f, 0x62, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x05, 0x6a, 0x6f, 0x62, 0x49, 0x64, 0x12, 0x17, 0x0a, 0x07, 0x74, 0x61, 0x73, 0x6b, 0x5f,
	0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x74, 0x61, 0x73, 0x6b, 0x49, 0x64,
	0x12, 0x1c, 0x0a, 0x09, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x03, 0x52, 0x09, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x22, 0xb3,
	0x02, 0x0a, 0x13, 0x54, 0x61, 0x73, 0x6b, 0x50, 0x72, 0x6f, 0x67, 0x72, 0x65, 0x73, 0x73, 0x65,
	0x64, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x12, 0x17, 0x0a, 0x07, 0x74, 0x61, 0x73, 0x6b, 0x5f, 0x69,
	0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x74, 0x61, 0x73, 0x6b, 0x49, 0x64, 0x12,
	0x21, 0x0a, 0x0c, 0x73, 0x65, 0x71, 0x75, 0x65, 0x6e, 0x63, 0x65, 0x5f, 0x6e, 0x75, 0x6d, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x03, 0x52, 0x0b, 0x73, 0x65, 0x71, 0x75, 0x65, 0x6e, 0x63, 0x65, 0x4e,
	0x75, 0x6d, 0x12, 0x1c, 0x0a, 0x09, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x03, 0x52, 0x09, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70,
	0x12, 0x27, 0x0a, 0x0f, 0x69, 0x74, 0x65, 0x6d, 0x73, 0x5f, 0x70, 0x72, 0x6f, 0x63, 0x65, 0x73,
	0x73, 0x65, 0x64, 0x18, 0x04, 0x20, 0x01, 0x28, 0x03, 0x52, 0x0e, 0x69, 0x74, 0x65, 0x6d, 0x73,
	0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x65, 0x64, 0x12, 0x1f, 0x0a, 0x0b, 0x65, 0x72, 0x72,
	0x6f, 0x72, 0x5f, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x18, 0x05, 0x20, 0x01, 0x28, 0x05, 0x52, 0x0a,
	0x65, 0x72, 0x72, 0x6f, 0x72, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x12, 0x18, 0x0a, 0x07, 0x6d, 0x65,
	0x73, 0x73, 0x61, 0x67, 0x65, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x6d, 0x65, 0x73,
	0x73, 0x61, 0x67, 0x65, 0x12, 0x29, 0x0a, 0x10, 0x70, 0x72, 0x6f, 0x67, 0x72, 0x65, 0x73, 0x73,
	0x5f, 0x64, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x73, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0f,
	0x70, 0x72, 0x6f, 0x67, 0x72, 0x65, 0x73, 0x73, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x73, 0x12,
	0x33, 0x0a, 0x0a, 0x63, 0x68, 0x65, 0x63, 0x6b, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x18, 0x08, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x13, 0x2e, 0x73, 0x63, 0x61, 0x6e, 0x6e, 0x65, 0x72, 0x2e, 0x43, 0x68,
	0x65, 0x63, 0x6b, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x52, 0x0a, 0x63, 0x68, 0x65, 0x63, 0x6b, 0x70,
	0x6f, 0x69, 0x6e, 0x74, 0x22, 0xe2, 0x01, 0x0a, 0x0a, 0x43, 0x68, 0x65, 0x63, 0x6b, 0x70, 0x6f,
	0x69, 0x6e, 0x74, 0x12, 0x17, 0x0a, 0x07, 0x74, 0x61, 0x73, 0x6b, 0x5f, 0x69, 0x64, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x74, 0x61, 0x73, 0x6b, 0x49, 0x64, 0x12, 0x1c, 0x0a, 0x09,
	0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x18, 0x02, 0x20, 0x01, 0x28, 0x03, 0x52,
	0x09, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x12, 0x21, 0x0a, 0x0c, 0x72, 0x65,
	0x73, 0x75, 0x6d, 0x65, 0x5f, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x0b, 0x72, 0x65, 0x73, 0x75, 0x6d, 0x65, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x12, 0x3d, 0x0a,
	0x08, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x18, 0x04, 0x20, 0x03, 0x28, 0x0b, 0x32,
	0x21, 0x2e, 0x73, 0x63, 0x61, 0x6e, 0x6e, 0x65, 0x72, 0x2e, 0x43, 0x68, 0x65, 0x63, 0x6b, 0x70,
	0x6f, 0x69, 0x6e, 0x74, 0x2e, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x45, 0x6e, 0x74,
	0x72, 0x79, 0x52, 0x08, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x1a, 0x3b, 0x0a, 0x0d,
	0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a,
	0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12,
	0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05,
	0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x22, 0x62, 0x0a, 0x12, 0x54, 0x61, 0x73,
	0x6b, 0x43, 0x6f, 0x6d, 0x70, 0x6c, 0x65, 0x74, 0x65, 0x64, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x12,
	0x15, 0x0a, 0x06, 0x6a, 0x6f, 0x62, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x05, 0x6a, 0x6f, 0x62, 0x49, 0x64, 0x12, 0x17, 0x0a, 0x07, 0x74, 0x61, 0x73, 0x6b, 0x5f, 0x69,
	0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x74, 0x61, 0x73, 0x6b, 0x49, 0x64, 0x12,
	0x1c, 0x0a, 0x09, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x18, 0x03, 0x20, 0x01,
	0x28, 0x03, 0x52, 0x09, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x22, 0x77, 0x0a,
	0x0f, 0x54, 0x61, 0x73, 0x6b, 0x46, 0x61, 0x69, 0x6c, 0x65, 0x64, 0x45, 0x76, 0x65, 0x6e, 0x74,
	0x12, 0x15, 0x0a, 0x06, 0x6a, 0x6f, 0x62, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x05, 0x6a, 0x6f, 0x62, 0x49, 0x64, 0x12, 0x17, 0x0a, 0x07, 0x74, 0x61, 0x73, 0x6b, 0x5f,
	0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x74, 0x61, 0x73, 0x6b, 0x49, 0x64,
	0x12, 0x1c, 0x0a, 0x09, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x03, 0x52, 0x09, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x12, 0x16,
	0x0a, 0x06, 0x72, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06,
	0x72, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x22, 0x4b, 0x0a, 0x12, 0x54, 0x61, 0x73, 0x6b, 0x48, 0x65,
	0x61, 0x72, 0x74, 0x62, 0x65, 0x61, 0x74, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x12, 0x17, 0x0a, 0x07,
	0x74, 0x61, 0x73, 0x6b, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x74,
	0x61, 0x73, 0x6b, 0x49, 0x64, 0x12, 0x1c, 0x0a, 0x09, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61,
	0x6d, 0x70, 0x18, 0x02, 0x20, 0x01, 0x28, 0x03, 0x52, 0x09, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74,
	0x61, 0x6d, 0x70, 0x22, 0xda, 0x01, 0x0a, 0x0f, 0x54, 0x61, 0x73, 0x6b, 0x52, 0x65, 0x73, 0x75,
	0x6d, 0x65, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x12, 0x15, 0x0a, 0x06, 0x6a, 0x6f, 0x62, 0x5f, 0x69,
	0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x6a, 0x6f, 0x62, 0x49, 0x64, 0x12, 0x17,
	0x0a, 0x07, 0x74, 0x61, 0x73, 0x6b, 0x5f, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x06, 0x74, 0x61, 0x73, 0x6b, 0x49, 0x64, 0x12, 0x1c, 0x0a, 0x09, 0x74, 0x69, 0x6d, 0x65, 0x73,
	0x74, 0x61, 0x6d, 0x70, 0x18, 0x03, 0x20, 0x01, 0x28, 0x03, 0x52, 0x09, 0x74, 0x69, 0x6d, 0x65,
	0x73, 0x74, 0x61, 0x6d, 0x70, 0x12, 0x21, 0x0a, 0x0c, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63,
	0x65, 0x5f, 0x75, 0x72, 0x69, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x72, 0x65, 0x73,
	0x6f, 0x75, 0x72, 0x63, 0x65, 0x55, 0x72, 0x69, 0x12, 0x21, 0x0a, 0x0c, 0x73, 0x65, 0x71, 0x75,
	0x65, 0x6e, 0x63, 0x65, 0x5f, 0x6e, 0x75, 0x6d, 0x18, 0x05, 0x20, 0x01, 0x28, 0x03, 0x52, 0x0b,
	0x73, 0x65, 0x71, 0x75, 0x65, 0x6e, 0x63, 0x65, 0x4e, 0x75, 0x6d, 0x12, 0x33, 0x0a, 0x0a, 0x63,
	0x68, 0x65, 0x63, 0x6b, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x13, 0x2e, 0x73, 0x63, 0x61, 0x6e, 0x6e, 0x65, 0x72, 0x2e, 0x43, 0x68, 0x65, 0x63, 0x6b, 0x70,
	0x6f, 0x69, 0x6e, 0x74, 0x52, 0x0a, 0x63, 0x68, 0x65, 0x63, 0x6b, 0x70, 0x6f, 0x69, 0x6e, 0x74,
	0x2a, 0xa4, 0x01, 0x0a, 0x0d, 0x53, 0x63, 0x61, 0x6e, 0x4a, 0x6f, 0x62, 0x53, 0x74, 0x61, 0x74,
	0x75, 0x73, 0x12, 0x1f, 0x0a, 0x1b, 0x53, 0x43, 0x41, 0x4e, 0x5f, 0x4a, 0x4f, 0x42, 0x5f, 0x53,
	0x54, 0x41, 0x54, 0x55, 0x53, 0x5f, 0x55, 0x4e, 0x53, 0x50, 0x45, 0x43, 0x49, 0x46, 0x49, 0x45,
	0x44, 0x10, 0x00, 0x12, 0x1a, 0x0a, 0x16, 0x53, 0x43, 0x41, 0x4e, 0x5f, 0x4a, 0x4f, 0x42, 0x5f,
	0x53, 0x54, 0x41, 0x54, 0x55, 0x53, 0x5f, 0x51, 0x55, 0x45, 0x55, 0x45, 0x44, 0x10, 0x01, 0x12,
	0x1b, 0x0a, 0x17, 0x53, 0x43, 0x41, 0x4e, 0x5f, 0x4a, 0x4f, 0x42, 0x5f, 0x53, 0x54, 0x41, 0x54,
	0x55, 0x53, 0x5f, 0x52, 0x55, 0x4e, 0x4e, 0x49, 0x4e, 0x47, 0x10, 0x02, 0x12, 0x1d, 0x0a, 0x19,
	0x53, 0x43, 0x41, 0x4e, 0x5f, 0x4a, 0x4f, 0x42, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x55, 0x53, 0x5f,
	0x43, 0x4f, 0x4d, 0x50, 0x4c, 0x45, 0x54, 0x45, 0x44, 0x10, 0x03, 0x12, 0x1a, 0x0a, 0x16, 0x53,
	0x43, 0x41, 0x4e, 0x5f, 0x4a, 0x4f, 0x42, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x55, 0x53, 0x5f, 0x46,
	0x41, 0x49, 0x4c, 0x45, 0x44, 0x10, 0x04, 0x2a, 0x79, 0x0a, 0x0a, 0x54, 0x61, 0x73, 0x6b, 0x53,
	0x74, 0x61, 0x74, 0x75, 0x73, 0x12, 0x1b, 0x0a, 0x17, 0x54, 0x41, 0x53, 0x4b, 0x5f, 0x53, 0x54,
	0x41, 0x54, 0x55, 0x53, 0x5f, 0x55, 0x4e, 0x53, 0x50, 0x45, 0x43, 0x49, 0x46, 0x49, 0x45, 0x44,
	0x10, 0x00, 0x12, 0x1b, 0x0a, 0x17, 0x54, 0x41, 0x53, 0x4b, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x55,
	0x53, 0x5f, 0x49, 0x4e, 0x5f, 0x50, 0x52, 0x4f, 0x47, 0x52, 0x45, 0x53, 0x53, 0x10, 0x01, 0x12,
	0x19, 0x0a, 0x15, 0x54, 0x41, 0x53, 0x4b, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x55, 0x53, 0x5f, 0x43,
	0x4f, 0x4d, 0x50, 0x4c, 0x45, 0x54, 0x45, 0x44, 0x10, 0x02, 0x12, 0x16, 0x0a, 0x12, 0x54, 0x41,
	0x53, 0x4b, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x55, 0x53, 0x5f, 0x46, 0x41, 0x49, 0x4c, 0x45, 0x44,
	0x10, 0x03, 0x42, 0x2e, 0x5a, 0x2c, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d,
	0x2f, 0x61, 0x68, 0x72, 0x61, 0x76, 0x2f, 0x67, 0x69, 0x74, 0x6c, 0x65, 0x61, 0x6b, 0x73, 0x2d,
	0x61, 0x72, 0x6d, 0x61, 0x64, 0x61, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x3b, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_proto_scanning_proto_rawDescOnce sync.Once
	file_proto_scanning_proto_rawDescData = file_proto_scanning_proto_rawDesc
)

func file_proto_scanning_proto_rawDescGZIP() []byte {
	file_proto_scanning_proto_rawDescOnce.Do(func() {
		file_proto_scanning_proto_rawDescData = protoimpl.X.CompressGZIP(file_proto_scanning_proto_rawDescData)
	})
	return file_proto_scanning_proto_rawDescData
}

var file_proto_scanning_proto_enumTypes = make([]protoimpl.EnumInfo, 2)
var file_proto_scanning_proto_msgTypes = make([]protoimpl.MessageInfo, 10)
var file_proto_scanning_proto_goTypes = []interface{}{
	(ScanJobStatus)(0),          // 0: scanner.ScanJobStatus
	(TaskStatus)(0),             // 1: scanner.TaskStatus
	(*ScanResult)(nil),          // 2: scanner.ScanResult
	(*Finding)(nil),             // 3: scanner.Finding
	(*TaskStartedEvent)(nil),    // 4: scanner.TaskStartedEvent
	(*TaskProgressedEvent)(nil), // 5: scanner.TaskProgressedEvent
	(*Checkpoint)(nil),          // 6: scanner.Checkpoint
	(*TaskCompletedEvent)(nil),  // 7: scanner.TaskCompletedEvent
	(*TaskFailedEvent)(nil),     // 8: scanner.TaskFailedEvent
	(*TaskHeartbeatEvent)(nil),  // 9: scanner.TaskHeartbeatEvent
	(*TaskResumeEvent)(nil),     // 10: scanner.TaskResumeEvent
	nil,                         // 11: scanner.Checkpoint.MetadataEntry
	(*structpb.Struct)(nil),     // 12: google.protobuf.Struct
}
var file_proto_scanning_proto_depIdxs = []int32{
	3,  // 0: scanner.ScanResult.findings:type_name -> scanner.Finding
	0,  // 1: scanner.ScanResult.status:type_name -> scanner.ScanJobStatus
	12, // 2: scanner.Finding.raw_finding:type_name -> google.protobuf.Struct
	6,  // 3: scanner.TaskProgressedEvent.checkpoint:type_name -> scanner.Checkpoint
	11, // 4: scanner.Checkpoint.metadata:type_name -> scanner.Checkpoint.MetadataEntry
	6,  // 5: scanner.TaskResumeEvent.checkpoint:type_name -> scanner.Checkpoint
	6,  // [6:6] is the sub-list for method output_type
	6,  // [6:6] is the sub-list for method input_type
	6,  // [6:6] is the sub-list for extension type_name
	6,  // [6:6] is the sub-list for extension extendee
	0,  // [0:6] is the sub-list for field type_name
}

func init() { file_proto_scanning_proto_init() }
func file_proto_scanning_proto_init() {
	if File_proto_scanning_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_proto_scanning_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ScanResult); i {
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
		file_proto_scanning_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Finding); i {
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
		file_proto_scanning_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TaskStartedEvent); i {
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
		file_proto_scanning_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TaskProgressedEvent); i {
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
		file_proto_scanning_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Checkpoint); i {
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
		file_proto_scanning_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TaskCompletedEvent); i {
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
		file_proto_scanning_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TaskFailedEvent); i {
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
		file_proto_scanning_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TaskHeartbeatEvent); i {
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
		file_proto_scanning_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TaskResumeEvent); i {
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
			RawDescriptor: file_proto_scanning_proto_rawDesc,
			NumEnums:      2,
			NumMessages:   10,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_proto_scanning_proto_goTypes,
		DependencyIndexes: file_proto_scanning_proto_depIdxs,
		EnumInfos:         file_proto_scanning_proto_enumTypes,
		MessageInfos:      file_proto_scanning_proto_msgTypes,
	}.Build()
	File_proto_scanning_proto = out.File
	file_proto_scanning_proto_rawDesc = nil
	file_proto_scanning_proto_goTypes = nil
	file_proto_scanning_proto_depIdxs = nil
}
