// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        v3.20.3
// source: proto/scanner/rules.proto

package scanner

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

// MatchCondition matches your "AllowlistMatchCondition" enum in Go (OR / AND).
type AllowlistMatchCondition int32

const (
	AllowlistMatchCondition_ALLOWLIST_MATCH_CONDITION_UNSPECIFIED AllowlistMatchCondition = 0
	AllowlistMatchCondition_ALLOWLIST_MATCH_OR                    AllowlistMatchCondition = 1
	AllowlistMatchCondition_ALLOWLIST_MATCH_AND                   AllowlistMatchCondition = 2
)

// Enum value maps for AllowlistMatchCondition.
var (
	AllowlistMatchCondition_name = map[int32]string{
		0: "ALLOWLIST_MATCH_CONDITION_UNSPECIFIED",
		1: "ALLOWLIST_MATCH_OR",
		2: "ALLOWLIST_MATCH_AND",
	}
	AllowlistMatchCondition_value = map[string]int32{
		"ALLOWLIST_MATCH_CONDITION_UNSPECIFIED": 0,
		"ALLOWLIST_MATCH_OR":                    1,
		"ALLOWLIST_MATCH_AND":                   2,
	}
)

func (x AllowlistMatchCondition) Enum() *AllowlistMatchCondition {
	p := new(AllowlistMatchCondition)
	*p = x
	return p
}

func (x AllowlistMatchCondition) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (AllowlistMatchCondition) Descriptor() protoreflect.EnumDescriptor {
	return file_proto_scanner_rules_proto_enumTypes[0].Descriptor()
}

func (AllowlistMatchCondition) Type() protoreflect.EnumType {
	return &file_proto_scanner_rules_proto_enumTypes[0]
}

func (x AllowlistMatchCondition) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use AllowlistMatchCondition.Descriptor instead.
func (AllowlistMatchCondition) EnumDescriptor() ([]byte, []int) {
	return file_proto_scanner_rules_proto_rawDescGZIP(), []int{0}
}

// Represents a single allowlist entry that could ignore certain commits, paths,
// etc.
type Allowlist struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Description    string                  `protobuf:"bytes,1,opt,name=description,proto3" json:"description,omitempty"`
	MatchCondition AllowlistMatchCondition `protobuf:"varint,2,opt,name=match_condition,json=matchCondition,proto3,enum=scanner.AllowlistMatchCondition" json:"match_condition,omitempty"`
	// List of commit SHAs to ignore.
	Commits []string `protobuf:"bytes,3,rep,name=commits,proto3" json:"commits,omitempty"`
	// List of file-path regex patterns to ignore.
	PathRegexes []string `protobuf:"bytes,4,rep,name=path_regexes,json=pathRegexes,proto3" json:"path_regexes,omitempty"`
	// List of content regex patterns to ignore.
	Regexes []string `protobuf:"bytes,5,rep,name=regexes,proto3" json:"regexes,omitempty"`
	// If "match", the above regexes apply to the matched secret snippet.
	// If "line", they apply to the entire line.
	// If empty, default is "matched secret".
	RegexTarget string `protobuf:"bytes,6,opt,name=regex_target,json=regexTarget,proto3" json:"regex_target,omitempty"`
	// Words that, if found, should ignore the finding.
	StopWords []string `protobuf:"bytes,7,rep,name=stop_words,json=stopWords,proto3" json:"stop_words,omitempty"`
}

func (x *Allowlist) Reset() {
	*x = Allowlist{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_scanner_rules_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Allowlist) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Allowlist) ProtoMessage() {}

func (x *Allowlist) ProtoReflect() protoreflect.Message {
	mi := &file_proto_scanner_rules_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Allowlist.ProtoReflect.Descriptor instead.
func (*Allowlist) Descriptor() ([]byte, []int) {
	return file_proto_scanner_rules_proto_rawDescGZIP(), []int{0}
}

func (x *Allowlist) GetDescription() string {
	if x != nil {
		return x.Description
	}
	return ""
}

func (x *Allowlist) GetMatchCondition() AllowlistMatchCondition {
	if x != nil {
		return x.MatchCondition
	}
	return AllowlistMatchCondition_ALLOWLIST_MATCH_CONDITION_UNSPECIFIED
}

func (x *Allowlist) GetCommits() []string {
	if x != nil {
		return x.Commits
	}
	return nil
}

func (x *Allowlist) GetPathRegexes() []string {
	if x != nil {
		return x.PathRegexes
	}
	return nil
}

func (x *Allowlist) GetRegexes() []string {
	if x != nil {
		return x.Regexes
	}
	return nil
}

func (x *Allowlist) GetRegexTarget() string {
	if x != nil {
		return x.RegexTarget
	}
	return ""
}

func (x *Allowlist) GetStopWords() []string {
	if x != nil {
		return x.StopWords
	}
	return nil
}

type RuleRequestedEvent struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *RuleRequestedEvent) Reset() {
	*x = RuleRequestedEvent{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_scanner_rules_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RuleRequestedEvent) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RuleRequestedEvent) ProtoMessage() {}

func (x *RuleRequestedEvent) ProtoReflect() protoreflect.Message {
	mi := &file_proto_scanner_rules_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RuleRequestedEvent.ProtoReflect.Descriptor instead.
func (*RuleRequestedEvent) Descriptor() ([]byte, []int) {
	return file_proto_scanner_rules_proto_rawDescGZIP(), []int{1}
}

type RulePublishingCompletedEvent struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *RulePublishingCompletedEvent) Reset() {
	*x = RulePublishingCompletedEvent{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_scanner_rules_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RulePublishingCompletedEvent) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RulePublishingCompletedEvent) ProtoMessage() {}

func (x *RulePublishingCompletedEvent) ProtoReflect() protoreflect.Message {
	mi := &file_proto_scanner_rules_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RulePublishingCompletedEvent.ProtoReflect.Descriptor instead.
func (*RulePublishingCompletedEvent) Descriptor() ([]byte, []int) {
	return file_proto_scanner_rules_proto_rawDescGZIP(), []int{2}
}

// Represents a single scanning rule.
type Rule struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Unique ID for the rule (DB: rules.rule_id).
	RuleId      string `protobuf:"bytes,1,opt,name=rule_id,json=ruleId,proto3" json:"rule_id,omitempty"`
	Description string `protobuf:"bytes,2,opt,name=description,proto3" json:"description,omitempty"`
	// Minimum Shannon entropy for a match to be considered a secret.
	Entropy float32 `protobuf:"fixed32,3,opt,name=entropy,proto3" json:"entropy,omitempty"`
	// If nonzero, the group index in the main regex to check entropy.
	SecretGroup int32 `protobuf:"varint,4,opt,name=secret_group,json=secretGroup,proto3" json:"secret_group,omitempty"`
	// The main detection regex (string form)
	Regex string `protobuf:"bytes,5,opt,name=regex,proto3" json:"regex,omitempty"`
	// A path-based regex (string form) to filter on file paths.
	Path     string   `protobuf:"bytes,6,opt,name=path,proto3" json:"path,omitempty"`
	Tags     []string `protobuf:"bytes,7,rep,name=tags,proto3" json:"tags,omitempty"`
	Keywords []string `protobuf:"bytes,8,rep,name=keywords,proto3" json:"keywords,omitempty"`
	// Zero or more allowlists that define exceptions.
	Allowlists []*Allowlist `protobuf:"bytes,9,rep,name=allowlists,proto3" json:"allowlists,omitempty"`
}

func (x *Rule) Reset() {
	*x = Rule{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_scanner_rules_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Rule) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Rule) ProtoMessage() {}

func (x *Rule) ProtoReflect() protoreflect.Message {
	mi := &file_proto_scanner_rules_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Rule.ProtoReflect.Descriptor instead.
func (*Rule) Descriptor() ([]byte, []int) {
	return file_proto_scanner_rules_proto_rawDescGZIP(), []int{3}
}

func (x *Rule) GetRuleId() string {
	if x != nil {
		return x.RuleId
	}
	return ""
}

func (x *Rule) GetDescription() string {
	if x != nil {
		return x.Description
	}
	return ""
}

func (x *Rule) GetEntropy() float32 {
	if x != nil {
		return x.Entropy
	}
	return 0
}

func (x *Rule) GetSecretGroup() int32 {
	if x != nil {
		return x.SecretGroup
	}
	return 0
}

func (x *Rule) GetRegex() string {
	if x != nil {
		return x.Regex
	}
	return ""
}

func (x *Rule) GetPath() string {
	if x != nil {
		return x.Path
	}
	return ""
}

func (x *Rule) GetTags() []string {
	if x != nil {
		return x.Tags
	}
	return nil
}

func (x *Rule) GetKeywords() []string {
	if x != nil {
		return x.Keywords
	}
	return nil
}

func (x *Rule) GetAllowlists() []*Allowlist {
	if x != nil {
		return x.Allowlists
	}
	return nil
}

// A single rule message for transmission.
type RuleMessage struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Rule *Rule  `protobuf:"bytes,1,opt,name=rule,proto3" json:"rule,omitempty"`
	Hash string `protobuf:"bytes,2,opt,name=hash,proto3" json:"hash,omitempty"` // Hash of the rule content for deduplication
}

func (x *RuleMessage) Reset() {
	*x = RuleMessage{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_scanner_rules_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RuleMessage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RuleMessage) ProtoMessage() {}

func (x *RuleMessage) ProtoReflect() protoreflect.Message {
	mi := &file_proto_scanner_rules_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RuleMessage.ProtoReflect.Descriptor instead.
func (*RuleMessage) Descriptor() ([]byte, []int) {
	return file_proto_scanner_rules_proto_rawDescGZIP(), []int{4}
}

func (x *RuleMessage) GetRule() *Rule {
	if x != nil {
		return x.Rule
	}
	return nil
}

func (x *RuleMessage) GetHash() string {
	if x != nil {
		return x.Hash
	}
	return ""
}

var File_proto_scanner_rules_proto protoreflect.FileDescriptor

var file_proto_scanner_rules_proto_rawDesc = []byte{
	0x0a, 0x19, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x73, 0x63, 0x61, 0x6e, 0x6e, 0x65, 0x72, 0x2f,
	0x72, 0x75, 0x6c, 0x65, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x07, 0x73, 0x63, 0x61,
	0x6e, 0x6e, 0x65, 0x72, 0x22, 0x91, 0x02, 0x0a, 0x09, 0x41, 0x6c, 0x6c, 0x6f, 0x77, 0x6c, 0x69,
	0x73, 0x74, 0x12, 0x20, 0x0a, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f,
	0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70,
	0x74, 0x69, 0x6f, 0x6e, 0x12, 0x49, 0x0a, 0x0f, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x5f, 0x63, 0x6f,
	0x6e, 0x64, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x20, 0x2e,
	0x73, 0x63, 0x61, 0x6e, 0x6e, 0x65, 0x72, 0x2e, 0x41, 0x6c, 0x6c, 0x6f, 0x77, 0x6c, 0x69, 0x73,
	0x74, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x43, 0x6f, 0x6e, 0x64, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x52,
	0x0e, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x43, 0x6f, 0x6e, 0x64, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x12,
	0x18, 0x0a, 0x07, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x73, 0x18, 0x03, 0x20, 0x03, 0x28, 0x09,
	0x52, 0x07, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x73, 0x12, 0x21, 0x0a, 0x0c, 0x70, 0x61, 0x74,
	0x68, 0x5f, 0x72, 0x65, 0x67, 0x65, 0x78, 0x65, 0x73, 0x18, 0x04, 0x20, 0x03, 0x28, 0x09, 0x52,
	0x0b, 0x70, 0x61, 0x74, 0x68, 0x52, 0x65, 0x67, 0x65, 0x78, 0x65, 0x73, 0x12, 0x18, 0x0a, 0x07,
	0x72, 0x65, 0x67, 0x65, 0x78, 0x65, 0x73, 0x18, 0x05, 0x20, 0x03, 0x28, 0x09, 0x52, 0x07, 0x72,
	0x65, 0x67, 0x65, 0x78, 0x65, 0x73, 0x12, 0x21, 0x0a, 0x0c, 0x72, 0x65, 0x67, 0x65, 0x78, 0x5f,
	0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x72, 0x65,
	0x67, 0x65, 0x78, 0x54, 0x61, 0x72, 0x67, 0x65, 0x74, 0x12, 0x1d, 0x0a, 0x0a, 0x73, 0x74, 0x6f,
	0x70, 0x5f, 0x77, 0x6f, 0x72, 0x64, 0x73, 0x18, 0x07, 0x20, 0x03, 0x28, 0x09, 0x52, 0x09, 0x73,
	0x74, 0x6f, 0x70, 0x57, 0x6f, 0x72, 0x64, 0x73, 0x22, 0x14, 0x0a, 0x12, 0x52, 0x75, 0x6c, 0x65,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x65, 0x64, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x22, 0x1e,
	0x0a, 0x1c, 0x52, 0x75, 0x6c, 0x65, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x73, 0x68, 0x69, 0x6e, 0x67,
	0x43, 0x6f, 0x6d, 0x70, 0x6c, 0x65, 0x74, 0x65, 0x64, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x22, 0x8c,
	0x02, 0x0a, 0x04, 0x52, 0x75, 0x6c, 0x65, 0x12, 0x17, 0x0a, 0x07, 0x72, 0x75, 0x6c, 0x65, 0x5f,
	0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x72, 0x75, 0x6c, 0x65, 0x49, 0x64,
	0x12, 0x20, 0x0a, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69,
	0x6f, 0x6e, 0x12, 0x18, 0x0a, 0x07, 0x65, 0x6e, 0x74, 0x72, 0x6f, 0x70, 0x79, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x02, 0x52, 0x07, 0x65, 0x6e, 0x74, 0x72, 0x6f, 0x70, 0x79, 0x12, 0x21, 0x0a, 0x0c,
	0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x5f, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x18, 0x04, 0x20, 0x01,
	0x28, 0x05, 0x52, 0x0b, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x47, 0x72, 0x6f, 0x75, 0x70, 0x12,
	0x14, 0x0a, 0x05, 0x72, 0x65, 0x67, 0x65, 0x78, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05,
	0x72, 0x65, 0x67, 0x65, 0x78, 0x12, 0x12, 0x0a, 0x04, 0x70, 0x61, 0x74, 0x68, 0x18, 0x06, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x04, 0x70, 0x61, 0x74, 0x68, 0x12, 0x12, 0x0a, 0x04, 0x74, 0x61, 0x67,
	0x73, 0x18, 0x07, 0x20, 0x03, 0x28, 0x09, 0x52, 0x04, 0x74, 0x61, 0x67, 0x73, 0x12, 0x1a, 0x0a,
	0x08, 0x6b, 0x65, 0x79, 0x77, 0x6f, 0x72, 0x64, 0x73, 0x18, 0x08, 0x20, 0x03, 0x28, 0x09, 0x52,
	0x08, 0x6b, 0x65, 0x79, 0x77, 0x6f, 0x72, 0x64, 0x73, 0x12, 0x32, 0x0a, 0x0a, 0x61, 0x6c, 0x6c,
	0x6f, 0x77, 0x6c, 0x69, 0x73, 0x74, 0x73, 0x18, 0x09, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x12, 0x2e,
	0x73, 0x63, 0x61, 0x6e, 0x6e, 0x65, 0x72, 0x2e, 0x41, 0x6c, 0x6c, 0x6f, 0x77, 0x6c, 0x69, 0x73,
	0x74, 0x52, 0x0a, 0x61, 0x6c, 0x6c, 0x6f, 0x77, 0x6c, 0x69, 0x73, 0x74, 0x73, 0x22, 0x44, 0x0a,
	0x0b, 0x52, 0x75, 0x6c, 0x65, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x21, 0x0a, 0x04,
	0x72, 0x75, 0x6c, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0d, 0x2e, 0x73, 0x63, 0x61,
	0x6e, 0x6e, 0x65, 0x72, 0x2e, 0x52, 0x75, 0x6c, 0x65, 0x52, 0x04, 0x72, 0x75, 0x6c, 0x65, 0x12,
	0x12, 0x0a, 0x04, 0x68, 0x61, 0x73, 0x68, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x68,
	0x61, 0x73, 0x68, 0x2a, 0x75, 0x0a, 0x17, 0x41, 0x6c, 0x6c, 0x6f, 0x77, 0x6c, 0x69, 0x73, 0x74,
	0x4d, 0x61, 0x74, 0x63, 0x68, 0x43, 0x6f, 0x6e, 0x64, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x29,
	0x0a, 0x25, 0x41, 0x4c, 0x4c, 0x4f, 0x57, 0x4c, 0x49, 0x53, 0x54, 0x5f, 0x4d, 0x41, 0x54, 0x43,
	0x48, 0x5f, 0x43, 0x4f, 0x4e, 0x44, 0x49, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x55, 0x4e, 0x53, 0x50,
	0x45, 0x43, 0x49, 0x46, 0x49, 0x45, 0x44, 0x10, 0x00, 0x12, 0x16, 0x0a, 0x12, 0x41, 0x4c, 0x4c,
	0x4f, 0x57, 0x4c, 0x49, 0x53, 0x54, 0x5f, 0x4d, 0x41, 0x54, 0x43, 0x48, 0x5f, 0x4f, 0x52, 0x10,
	0x01, 0x12, 0x17, 0x0a, 0x13, 0x41, 0x4c, 0x4c, 0x4f, 0x57, 0x4c, 0x49, 0x53, 0x54, 0x5f, 0x4d,
	0x41, 0x54, 0x43, 0x48, 0x5f, 0x41, 0x4e, 0x44, 0x10, 0x02, 0x42, 0x38, 0x5a, 0x36, 0x67, 0x69,
	0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x61, 0x68, 0x72, 0x61, 0x76, 0x2f, 0x67,
	0x69, 0x74, 0x6c, 0x65, 0x61, 0x6b, 0x73, 0x2d, 0x61, 0x72, 0x6d, 0x61, 0x64, 0x61, 0x2f, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x73, 0x63, 0x61, 0x6e, 0x6e, 0x65, 0x72, 0x3b, 0x73, 0x63, 0x61,
	0x6e, 0x6e, 0x65, 0x72, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_proto_scanner_rules_proto_rawDescOnce sync.Once
	file_proto_scanner_rules_proto_rawDescData = file_proto_scanner_rules_proto_rawDesc
)

func file_proto_scanner_rules_proto_rawDescGZIP() []byte {
	file_proto_scanner_rules_proto_rawDescOnce.Do(func() {
		file_proto_scanner_rules_proto_rawDescData = protoimpl.X.CompressGZIP(file_proto_scanner_rules_proto_rawDescData)
	})
	return file_proto_scanner_rules_proto_rawDescData
}

var file_proto_scanner_rules_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_proto_scanner_rules_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_proto_scanner_rules_proto_goTypes = []interface{}{
	(AllowlistMatchCondition)(0),         // 0: scanner.AllowlistMatchCondition
	(*Allowlist)(nil),                    // 1: scanner.Allowlist
	(*RuleRequestedEvent)(nil),           // 2: scanner.RuleRequestedEvent
	(*RulePublishingCompletedEvent)(nil), // 3: scanner.RulePublishingCompletedEvent
	(*Rule)(nil),                         // 4: scanner.Rule
	(*RuleMessage)(nil),                  // 5: scanner.RuleMessage
}
var file_proto_scanner_rules_proto_depIdxs = []int32{
	0, // 0: scanner.Allowlist.match_condition:type_name -> scanner.AllowlistMatchCondition
	1, // 1: scanner.Rule.allowlists:type_name -> scanner.Allowlist
	4, // 2: scanner.RuleMessage.rule:type_name -> scanner.Rule
	3, // [3:3] is the sub-list for method output_type
	3, // [3:3] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_proto_scanner_rules_proto_init() }
func file_proto_scanner_rules_proto_init() {
	if File_proto_scanner_rules_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_proto_scanner_rules_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Allowlist); i {
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
		file_proto_scanner_rules_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RuleRequestedEvent); i {
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
		file_proto_scanner_rules_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RulePublishingCompletedEvent); i {
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
		file_proto_scanner_rules_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Rule); i {
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
		file_proto_scanner_rules_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RuleMessage); i {
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
			RawDescriptor: file_proto_scanner_rules_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_proto_scanner_rules_proto_goTypes,
		DependencyIndexes: file_proto_scanner_rules_proto_depIdxs,
		EnumInfos:         file_proto_scanner_rules_proto_enumTypes,
		MessageInfos:      file_proto_scanner_rules_proto_msgTypes,
	}.Build()
	File_proto_scanner_rules_proto = out.File
	file_proto_scanner_rules_proto_rawDesc = nil
	file_proto_scanner_rules_proto_goTypes = nil
	file_proto_scanner_rules_proto_depIdxs = nil
}
