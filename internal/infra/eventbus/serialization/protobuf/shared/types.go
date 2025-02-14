// Package shared provides common serialization utilities for converting between
// domain and protobuf types that are used across multiple domains.
package shared

import (
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
	serializationerrors "github.com/ahrav/gitleaks-armada/internal/infra/eventbus/serialization/errors"
	pb "github.com/ahrav/gitleaks-armada/proto"
)

var sourceTypeToProto = map[shared.SourceType]pb.SourceType{
	shared.SourceTypeGitHub: pb.SourceType_SOURCE_TYPE_GITHUB,
	shared.SourceTypeS3:     pb.SourceType_SOURCE_TYPE_S3,
	shared.SourceTypeURL:    pb.SourceType_SOURCE_TYPE_URL,
}

var protoToSourceType = map[pb.SourceType]shared.SourceType{
	pb.SourceType_SOURCE_TYPE_GITHUB: shared.SourceTypeGitHub,
	pb.SourceType_SOURCE_TYPE_S3:     shared.SourceTypeS3,
	pb.SourceType_SOURCE_TYPE_URL:    shared.SourceTypeURL,
}

// SourceTypeToProto converts a domain SourceType to its protobuf representation
func SourceTypeToProto(st shared.SourceType) (pb.SourceType, error) {
	if pbType, exists := sourceTypeToProto[st]; exists {
		return pbType, nil
	}
	return pb.SourceType_SOURCE_TYPE_UNSPECIFIED, serializationerrors.ErrInvalidSourceType{Value: st}
}

// ProtoToSourceType converts a protobuf SourceType to its domain representation
func ProtoToSourceType(pbType pb.SourceType) (shared.SourceType, error) {
	if domainType, exists := protoToSourceType[pbType]; exists {
		return domainType, nil
	}
	return "", serializationerrors.ErrInvalidSourceType{Value: pbType}
}
