package enumeration

import (
	"github.com/google/uuid"

	"github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
	pb "github.com/ahrav/gitleaks-armada/proto"
)

var taskSourceTypeToProto = map[shared.SourceType]pb.SourceType{
	shared.SourceTypeGitHub: pb.SourceType_SOURCE_TYPE_GITHUB,
	shared.SourceTypeS3:     pb.SourceType_SOURCE_TYPE_S3,
	shared.SourceTypeURL:    pb.SourceType_SOURCE_TYPE_URL,
}

// TaskToProto converts an enumeration.Task to its protobuf representation (pb.EnumerationTask).
func TaskToProto(t *enumeration.Task, jobID uuid.UUID) *pb.EnumerationTask {
	tsk := &pb.EnumerationTask{
		TaskId:      t.ID.String(),
		JobId:       jobID.String(),
		SourceType:  taskSourceTypeToProto[t.SourceType],
		SessionId:   t.SessionID().String(),
		ResourceUri: t.ResourceURI(),
		Metadata:    t.Metadata(),
	}
	if t.Credentials() == nil {
		// If no credentials, we can pass a nil or an empty TaskCredentials
		return tsk
	}

	tsk.Credentials = ToProtoCredentials(t.Credentials())
	return tsk
}

var protoSourceTypeToTaskSourceType = map[pb.SourceType]shared.SourceType{
	pb.SourceType_SOURCE_TYPE_GITHUB: shared.SourceTypeGitHub,
	pb.SourceType_SOURCE_TYPE_S3:     shared.SourceTypeS3,
	pb.SourceType_SOURCE_TYPE_URL:    shared.SourceTypeURL,
}

// ProtoToTask converts a protobuf EnumerationTask to a domain Task.
func ProtoToTask(pt *pb.EnumerationTask) *enumeration.Task {
	var creds *enumeration.TaskCredentials
	if pt.Credentials != nil {
		creds = ProtoToDomainCredentials(pt.Credentials)
	}

	return enumeration.ReconstructTask(
		uuid.MustParse(pt.TaskId),
		protoSourceTypeToTaskSourceType[pt.SourceType],
		uuid.MustParse(pt.SessionId),
		pt.ResourceUri,
		pt.Metadata,
		creds,
	)
}

// ToProtoCredentials converts domain.TaskCredentials -> pb.TaskCredentials.
func ToProtoCredentials(c *enumeration.TaskCredentials) *pb.TaskCredentials {
	if c == nil {
		return nil
	}
	switch c.Type {
	case enumeration.CredentialTypeGitHub:
		return &pb.TaskCredentials{
			Auth: &pb.TaskCredentials_Github{
				Github: &pb.GitHubCredentials{
					AuthToken: c.Values["auth_token"].(string),
				},
			},
		}
	case enumeration.CredentialTypeS3:
		return &pb.TaskCredentials{
			Auth: &pb.TaskCredentials_S3{
				S3: &pb.S3Credentials{
					AccessKey:    c.Values["access_key"].(string),
					SecretKey:    c.Values["secret_key"].(string),
					SessionToken: c.Values["session_token"].(string),
				},
			},
		}
	case enumeration.CredentialTypeUnauthenticated:
		return &pb.TaskCredentials{
			Auth: &pb.TaskCredentials_Unauthenticated{
				Unauthenticated: &pb.UnauthenticatedCredentials{},
			},
		}
	default:
		// If it's an unsupported credential, return nil or handle error
		return nil
	}
}

// ProtoToDomainCredentials converts pb.TaskCredentials -> domain.TaskCredentials.
func ProtoToDomainCredentials(pc *pb.TaskCredentials) *enumeration.TaskCredentials {
	if pc == nil {
		return nil
	}
	switch auth := pc.Auth.(type) {
	case *pb.TaskCredentials_Github:
		return &enumeration.TaskCredentials{
			Type: enumeration.CredentialTypeGitHub,
			Values: map[string]any{
				"auth_token": auth.Github.AuthToken,
			},
		}
	case *pb.TaskCredentials_S3:
		return &enumeration.TaskCredentials{
			Type: enumeration.CredentialTypeS3,
			Values: map[string]any{
				"access_key":    auth.S3.AccessKey,
				"secret_key":    auth.S3.SecretKey,
				"session_token": auth.S3.SessionToken,
			},
		}
	case *pb.TaskCredentials_Unauthenticated:
		return &enumeration.TaskCredentials{
			Type:   enumeration.CredentialTypeUnauthenticated,
			Values: map[string]any{},
		}
	default:
		// If none match, treat it as unsupported or unspecified
		return &enumeration.TaskCredentials{
			Type:   enumeration.CredentialTypeUnspecified,
			Values: map[string]any{},
		}
	}
}
