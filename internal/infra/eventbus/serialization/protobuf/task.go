package protobuf

import (
	"github.com/ahrav/gitleaks-armada/internal/domain/task"
	pb "github.com/ahrav/gitleaks-armada/proto/scanner"
)

// TaskToProto converts a domain Task to its protobuf representation (pb.ScanTask).
func TaskToProto(t task.Task) *pb.ScanTask {
	if t.Credentials == nil {
		// If no credentials, we can pass a nil or an empty TaskCredentials
		return &pb.ScanTask{
			TaskId:      t.TaskID,
			ResourceUri: t.ResourceURI,
			Metadata:    t.Metadata,
			// Credentials: nil,
		}
	}

	return &pb.ScanTask{
		TaskId:      t.TaskID,
		ResourceUri: t.ResourceURI,
		Metadata:    t.Metadata,
		Credentials: ToProtoCredentials(t.Credentials),
		// Optionally set SourceType if you track that in domain
		// SourceType: pb.SourceType_SOURCE_TYPE_GITHUB, etc.
	}
}

// ProtoToTask converts a protobuf ScanTask to a domain Task.
func ProtoToTask(pt *pb.ScanTask) task.Task {
	var creds *task.TaskCredentials
	if pt.Credentials != nil {
		creds = ProtoToDomainCredentials(pt.Credentials)
	}

	return task.Task{
		TaskID:      pt.TaskId,
		ResourceURI: pt.ResourceUri,
		Metadata:    pt.Metadata,
		Credentials: creds,
	}
}

// ToProtoCredentials converts domain.TaskCredentials -> pb.TaskCredentials.
// (Already provided in your snippet, but included here for completeness.)
func ToProtoCredentials(c *task.TaskCredentials) *pb.TaskCredentials {
	if c == nil {
		return nil
	}
	switch c.Type {
	case task.CredentialTypeGitHub:
		return &pb.TaskCredentials{
			Auth: &pb.TaskCredentials_Github{
				Github: &pb.GitHubCredentials{
					AuthToken: c.Values["auth_token"].(string),
				},
			},
		}
	case task.CredentialTypeS3:
		return &pb.TaskCredentials{
			Auth: &pb.TaskCredentials_S3{
				S3: &pb.S3Credentials{
					AccessKey:    c.Values["access_key"].(string),
					SecretKey:    c.Values["secret_key"].(string),
					SessionToken: c.Values["session_token"].(string),
				},
			},
		}
	case task.CredentialTypeUnauthenticated:
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
func ProtoToDomainCredentials(pc *pb.TaskCredentials) *task.TaskCredentials {
	if pc == nil {
		return nil
	}
	switch auth := pc.Auth.(type) {
	case *pb.TaskCredentials_Github:
		return &task.TaskCredentials{
			Type: task.CredentialTypeGitHub,
			Values: map[string]any{
				"auth_token": auth.Github.AuthToken,
			},
		}
	case *pb.TaskCredentials_S3:
		return &task.TaskCredentials{
			Type: task.CredentialTypeS3,
			Values: map[string]any{
				"access_key":    auth.S3.AccessKey,
				"secret_key":    auth.S3.SecretKey,
				"session_token": auth.S3.SessionToken,
			},
		}
	case *pb.TaskCredentials_Unauthenticated:
		return &task.TaskCredentials{
			Type:   task.CredentialTypeUnauthenticated,
			Values: map[string]any{},
		}
	default:
		// If none match, treat it as unsupported or unspecified
		return &task.TaskCredentials{
			Type:   task.CredentialTypeUnspecified,
			Values: map[string]any{},
		}
	}
}
