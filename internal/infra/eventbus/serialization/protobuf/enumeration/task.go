package enumeration

import (
	"fmt"

	"github.com/google/uuid"

	"github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
	serializationerrors "github.com/ahrav/gitleaks-armada/internal/infra/eventbus/serialization/errors"
	pb "github.com/ahrav/gitleaks-armada/proto"
)

var taskSourceTypeToProto = map[shared.SourceType]pb.SourceType{
	shared.SourceTypeGitHub: pb.SourceType_SOURCE_TYPE_GITHUB,
	shared.SourceTypeS3:     pb.SourceType_SOURCE_TYPE_S3,
	shared.SourceTypeURL:    pb.SourceType_SOURCE_TYPE_URL,
}

// TaskToProto converts an enumeration.Task to its protobuf representation (pb.EnumerationTask).
func TaskToProto(t *enumeration.Task, jobID uuid.UUID) (*pb.EnumerationTask, error) {
	if t == nil {
		return nil, serializationerrors.ErrNilEvent{EventType: "EnumerationTask"}
	}

	sourceType, exists := taskSourceTypeToProto[t.SourceType]
	if !exists {
		return nil, serializationerrors.ErrInvalidSourceType{Value: t.SourceType}
	}

	tsk := &pb.EnumerationTask{
		TaskId:      t.ID.String(),
		JobId:       jobID.String(),
		SourceType:  sourceType,
		SessionId:   t.SessionID().String(),
		ResourceUri: t.ResourceURI(),
		Metadata:    t.Metadata(),
	}

	if t.Credentials() != nil {
		creds, err := ToProtoCredentials(t.Credentials())
		if err != nil {
			return nil, err
		}
		tsk.Credentials = creds
	}

	return tsk, nil
}

var protoSourceTypeToTaskSourceType = map[pb.SourceType]shared.SourceType{
	pb.SourceType_SOURCE_TYPE_GITHUB: shared.SourceTypeGitHub,
	pb.SourceType_SOURCE_TYPE_S3:     shared.SourceTypeS3,
	pb.SourceType_SOURCE_TYPE_URL:    shared.SourceTypeURL,
}

// ProtoToTask converts a protobuf EnumerationTask to a domain Task.
func ProtoToTask(pt *pb.EnumerationTask) (*enumeration.Task, error) {
	if pt == nil {
		return nil, serializationerrors.ErrNilEvent{EventType: "EnumerationTask"}
	}

	taskID, err := uuid.Parse(pt.TaskId)
	if err != nil {
		return nil, serializationerrors.ErrInvalidUUID{Field: "task ID", Err: err}
	}

	sessionID, err := uuid.Parse(pt.SessionId)
	if err != nil {
		return nil, serializationerrors.ErrInvalidUUID{Field: "session ID", Err: err}
	}

	sourceType, exists := protoSourceTypeToTaskSourceType[pt.SourceType]
	if !exists {
		return nil, serializationerrors.ErrInvalidSourceType{Value: pt.SourceType}
	}

	var creds *enumeration.TaskCredentials
	if pt.Credentials != nil {
		var err error
		creds, err = ProtoToDomainCredentials(pt.Credentials)
		if err != nil {
			return nil, err
		}
	}

	return enumeration.ReconstructTask(
		taskID,
		sourceType,
		sessionID,
		pt.ResourceUri,
		pt.Metadata,
		creds,
	), nil
}

// ToProtoCredentials converts domain.TaskCredentials -> pb.TaskCredentials.
func ToProtoCredentials(c *enumeration.TaskCredentials) (*pb.TaskCredentials, error) {
	if c == nil {
		return nil, nil
	}

	switch c.Type {
	case enumeration.CredentialTypeGitHub:
		authToken, ok := c.Values["auth_token"].(string)
		if !ok {
			return nil, fmt.Errorf("invalid GitHub auth token")
		}
		return &pb.TaskCredentials{
			Auth: &pb.TaskCredentials_Github{
				Github: &pb.GitHubCredentials{
					AuthToken: authToken,
				},
			},
		}, nil

	case enumeration.CredentialTypeS3:
		accessKey, ok1 := c.Values["access_key"].(string)
		secretKey, ok2 := c.Values["secret_key"].(string)
		sessionToken, ok3 := c.Values["session_token"].(string)
		if !ok1 || !ok2 || !ok3 {
			return nil, fmt.Errorf("invalid S3 credentials")
		}
		return &pb.TaskCredentials{
			Auth: &pb.TaskCredentials_S3{
				S3: &pb.S3Credentials{
					AccessKey:    accessKey,
					SecretKey:    secretKey,
					SessionToken: sessionToken,
				},
			},
		}, nil

	case enumeration.CredentialTypeUnauthenticated:
		return &pb.TaskCredentials{
			Auth: &pb.TaskCredentials_Unauthenticated{
				Unauthenticated: &pb.UnauthenticatedCredentials{},
			},
		}, nil

	default:
		return nil, fmt.Errorf("unsupported credential type: %s", c.Type)
	}
}

// ProtoToDomainCredentials converts pb.TaskCredentials -> domain.TaskCredentials.
func ProtoToDomainCredentials(pc *pb.TaskCredentials) (*enumeration.TaskCredentials, error) {
	if pc == nil {
		return nil, nil
	}

	switch auth := pc.Auth.(type) {
	case *pb.TaskCredentials_Github:
		if auth.Github == nil {
			return nil, fmt.Errorf("nil GitHub credentials")
		}
		return &enumeration.TaskCredentials{
			Type: enumeration.CredentialTypeGitHub,
			Values: map[string]any{
				"auth_token": auth.Github.AuthToken,
			},
		}, nil

	case *pb.TaskCredentials_S3:
		if auth.S3 == nil {
			return nil, fmt.Errorf("nil S3 credentials")
		}
		return &enumeration.TaskCredentials{
			Type: enumeration.CredentialTypeS3,
			Values: map[string]any{
				"access_key":    auth.S3.AccessKey,
				"secret_key":    auth.S3.SecretKey,
				"session_token": auth.S3.SessionToken,
			},
		}, nil

	case *pb.TaskCredentials_Unauthenticated:
		return &enumeration.TaskCredentials{
			Type:   enumeration.CredentialTypeUnauthenticated,
			Values: map[string]any{},
		}, nil

	default:
		return nil, fmt.Errorf("unsupported credential type")
	}
}
