package enumeration

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
	serializationerrors "github.com/ahrav/gitleaks-armada/internal/infra/eventbus/serialization/errors"
	pb "github.com/ahrav/gitleaks-armada/proto"
)

func TestTaskToProto(t *testing.T) {
	t.Run("successful conversion with GitHub credentials", func(t *testing.T) {
		taskID := uuid.New()
		jobID := uuid.New()
		sessionID := uuid.New()
		resourceURI := "https://github.com/org/repo"
		metadata := map[string]string{"key": "value"}

		creds := &enumeration.TaskCredentials{
			Type: enumeration.CredentialTypeGitHub,
			Values: map[string]any{
				"auth_token": "github-token",
			},
		}

		task := enumeration.ReconstructTask(
			taskID,
			shared.SourceTypeGitHub,
			sessionID,
			resourceURI,
			metadata,
			creds,
		)

		protoTask, err := TaskToProto(task, jobID)
		require.NoError(t, err)
		require.NotNil(t, protoTask)
		assert.Equal(t, taskID.String(), protoTask.TaskId)
		assert.Equal(t, jobID.String(), protoTask.JobId)
		assert.Equal(t, sessionID.String(), protoTask.SessionId)
		assert.Equal(t, resourceURI, protoTask.ResourceUri)
		assert.Equal(t, metadata, protoTask.Metadata)
		assert.Equal(t, pb.SourceType_SOURCE_TYPE_GITHUB, protoTask.SourceType)

		require.NotNil(t, protoTask.Credentials)
		githubCreds := protoTask.Credentials.GetGithub()
		require.NotNil(t, githubCreds)
		assert.Equal(t, "github-token", githubCreds.AuthToken)
	})

	t.Run("successful conversion with S3 credentials", func(t *testing.T) {
		taskID := uuid.New()
		jobID := uuid.New()
		sessionID := uuid.New()
		resourceURI := "s3://bucket/path"
		metadata := map[string]string{"key": "value"}

		creds := &enumeration.TaskCredentials{
			Type: enumeration.CredentialTypeS3,
			Values: map[string]any{
				"access_key":    "access-key",
				"secret_key":    "secret-key",
				"session_token": "session-token",
			},
		}

		task := enumeration.ReconstructTask(
			taskID,
			shared.SourceTypeS3,
			sessionID,
			resourceURI,
			metadata,
			creds,
		)

		protoTask, err := TaskToProto(task, jobID)
		require.NoError(t, err)
		require.NotNil(t, protoTask)
		assert.Equal(t, pb.SourceType_SOURCE_TYPE_S3, protoTask.SourceType)

		require.NotNil(t, protoTask.Credentials)
		s3Creds := protoTask.Credentials.GetS3()
		require.NotNil(t, s3Creds)
		assert.Equal(t, "access-key", s3Creds.AccessKey)
		assert.Equal(t, "secret-key", s3Creds.SecretKey)
		assert.Equal(t, "session-token", s3Creds.SessionToken)
	})

	t.Run("successful conversion with no credentials", func(t *testing.T) {
		taskID := uuid.New()
		jobID := uuid.New()
		sessionID := uuid.New()
		resourceURI := "http://example.com"

		task := enumeration.ReconstructTask(
			taskID,
			shared.SourceTypeURL,
			sessionID,
			resourceURI,
			nil,
			nil,
		)

		protoTask, err := TaskToProto(task, jobID)
		require.NoError(t, err)
		require.NotNil(t, protoTask)
		assert.Equal(t, pb.SourceType_SOURCE_TYPE_URL, protoTask.SourceType)
		assert.Nil(t, protoTask.Credentials)
	})

	t.Run("error cases", func(t *testing.T) {
		testCases := []struct {
			name    string
			task    *enumeration.Task
			jobID   uuid.UUID
			wantErr error
		}{
			{
				name:    "nil task",
				task:    nil,
				jobID:   uuid.New(),
				wantErr: serializationerrors.ErrNilEvent{EventType: "EnumerationTask"},
			},
			{
				name: "invalid source type",
				task: enumeration.ReconstructTask(
					uuid.New(),
					shared.SourceTypeUnspecified,
					uuid.New(),
					"uri",
					nil,
					nil,
				),
				jobID:   uuid.New(),
				wantErr: serializationerrors.ErrInvalidSourceType{Value: shared.SourceTypeUnspecified},
			},
			{
				name: "invalid GitHub credentials",
				task: enumeration.ReconstructTask(
					uuid.New(),
					shared.SourceTypeGitHub,
					uuid.New(),
					"uri",
					nil,
					&enumeration.TaskCredentials{
						Type:   enumeration.CredentialTypeGitHub,
						Values: map[string]any{"auth_token": 123}, // invalid type
					},
				),
				jobID:   uuid.New(),
				wantErr: fmt.Errorf("invalid GitHub auth token"),
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := TaskToProto(tc.task, tc.jobID)
				assert.IsType(t, tc.wantErr, err)
			})
		}
	})
}

func TestProtoToTask(t *testing.T) {
	t.Run("successful conversion with GitHub credentials", func(t *testing.T) {
		taskID := uuid.New()
		jobID := uuid.New()
		sessionID := uuid.New()
		resourceURI := "https://github.com/org/repo"
		metadata := map[string]string{"key": "value"}

		protoTask := &pb.EnumerationTask{
			TaskId:      taskID.String(),
			JobId:       jobID.String(),
			SessionId:   sessionID.String(),
			ResourceUri: resourceURI,
			Metadata:    metadata,
			SourceType:  pb.SourceType_SOURCE_TYPE_GITHUB,
			Credentials: &pb.TaskCredentials{
				Auth: &pb.TaskCredentials_Github{
					Github: &pb.GitHubCredentials{
						AuthToken: "github-token",
					},
				},
			},
		}

		task, err := ProtoToTask(protoTask)
		require.NoError(t, err)
		require.NotNil(t, task)
		assert.Equal(t, taskID, task.ID)
		assert.Equal(t, sessionID, task.SessionID())
		assert.Equal(t, resourceURI, task.ResourceURI())
		assert.Equal(t, metadata, task.Metadata())
		assert.Equal(t, shared.SourceTypeGitHub, task.SourceType)

		creds := task.Credentials()
		require.NotNil(t, creds)
		assert.Equal(t, enumeration.CredentialTypeGitHub, creds.Type)
		assert.Equal(t, "github-token", creds.Values["auth_token"])
	})

	t.Run("successful conversion with S3 credentials", func(t *testing.T) {
		taskID := uuid.New()
		sessionID := uuid.New()

		protoTask := &pb.EnumerationTask{
			TaskId:     taskID.String(),
			SessionId:  sessionID.String(),
			SourceType: pb.SourceType_SOURCE_TYPE_S3,
			Credentials: &pb.TaskCredentials{
				Auth: &pb.TaskCredentials_S3{
					S3: &pb.S3Credentials{
						AccessKey:    "access-key",
						SecretKey:    "secret-key",
						SessionToken: "session-token",
					},
				},
			},
		}

		task, err := ProtoToTask(protoTask)
		require.NoError(t, err)
		require.NotNil(t, task)
		assert.Equal(t, shared.SourceTypeS3, task.SourceType)

		creds := task.Credentials()
		require.NotNil(t, creds)
		assert.Equal(t, enumeration.CredentialTypeS3, creds.Type)
		assert.Equal(t, "access-key", creds.Values["access_key"])
		assert.Equal(t, "secret-key", creds.Values["secret_key"])
		assert.Equal(t, "session-token", creds.Values["session_token"])
	})

	t.Run("successful conversion with unauthenticated credentials", func(t *testing.T) {
		taskID := uuid.New()
		sessionID := uuid.New()

		protoTask := &pb.EnumerationTask{
			TaskId:     taskID.String(),
			SessionId:  sessionID.String(),
			SourceType: pb.SourceType_SOURCE_TYPE_URL,
			Credentials: &pb.TaskCredentials{
				Auth: &pb.TaskCredentials_Unauthenticated{
					Unauthenticated: &pb.UnauthenticatedCredentials{},
				},
			},
		}

		task, err := ProtoToTask(protoTask)
		require.NoError(t, err)
		require.NotNil(t, task)

		creds := task.Credentials()
		require.NotNil(t, creds)
		assert.Equal(t, enumeration.CredentialTypeUnauthenticated, creds.Type)
		assert.Empty(t, creds.Values)
	})

	t.Run("successful conversion with no credentials", func(t *testing.T) {
		taskID := uuid.New()
		sessionID := uuid.New()

		protoTask := &pb.EnumerationTask{
			TaskId:     taskID.String(),
			SessionId:  sessionID.String(),
			SourceType: pb.SourceType_SOURCE_TYPE_URL,
		}

		task, err := ProtoToTask(protoTask)
		require.NoError(t, err)
		require.NotNil(t, task)
		assert.Nil(t, task.Credentials())
	})

	t.Run("error cases", func(t *testing.T) {
		testCases := []struct {
			name      string
			protoTask *pb.EnumerationTask
			wantErr   error
		}{
			{
				name:      "nil task",
				protoTask: nil,
				wantErr:   serializationerrors.ErrNilEvent{EventType: "EnumerationTask"},
			},
			{
				name: "invalid task ID",
				protoTask: &pb.EnumerationTask{
					TaskId:    "invalid-uuid",
					SessionId: uuid.New().String(),
				},
				wantErr: serializationerrors.ErrInvalidUUID{Field: "task ID"},
			},
			{
				name: "invalid session ID",
				protoTask: &pb.EnumerationTask{
					TaskId:    uuid.New().String(),
					SessionId: "invalid-uuid",
				},
				wantErr: serializationerrors.ErrInvalidUUID{Field: "session ID"},
			},
			{
				name: "invalid source type",
				protoTask: &pb.EnumerationTask{
					TaskId:     uuid.New().String(),
					SessionId:  uuid.New().String(),
					SourceType: pb.SourceType(-1),
				},
				wantErr: serializationerrors.ErrInvalidSourceType{Value: pb.SourceType(-1)},
			},
			{
				name: "nil GitHub credentials",
				protoTask: &pb.EnumerationTask{
					TaskId:     uuid.New().String(),
					SessionId:  uuid.New().String(),
					SourceType: pb.SourceType_SOURCE_TYPE_GITHUB,
					Credentials: &pb.TaskCredentials{
						Auth: &pb.TaskCredentials_Github{},
					},
				},
				wantErr: fmt.Errorf("nil GitHub credentials"),
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := ProtoToTask(tc.protoTask)
				assert.IsType(t, tc.wantErr, err)
			})
		}
	})
}

func TestCredentialsConversion(t *testing.T) {
	t.Run("GitHub credentials conversion", func(t *testing.T) {
		domainCreds := &enumeration.TaskCredentials{
			Type:   enumeration.CredentialTypeGitHub,
			Values: map[string]any{"auth_token": "github-token"},
		}

		protoCreds, err := ToProtoCredentials(domainCreds)
		require.NoError(t, err)
		require.NotNil(t, protoCreds)
		githubCreds := protoCreds.GetGithub()
		require.NotNil(t, githubCreds)
		assert.Equal(t, "github-token", githubCreds.AuthToken)

		convertedCreds, err := ProtoToDomainCredentials(protoCreds)
		require.NoError(t, err)
		require.NotNil(t, convertedCreds)
		assert.Equal(t, enumeration.CredentialTypeGitHub, convertedCreds.Type)
		assert.Equal(t, "github-token", convertedCreds.Values["auth_token"])
	})

	t.Run("nil credentials handling", func(t *testing.T) {
		protoCreds, err := ToProtoCredentials(nil)
		require.NoError(t, err)
		assert.Nil(t, protoCreds)

		domainCreds, err := ProtoToDomainCredentials(nil)
		require.NoError(t, err)
		assert.Nil(t, domainCreds)
	})

	t.Run("error cases", func(t *testing.T) {
		testCases := []struct {
			name    string
			creds   *enumeration.TaskCredentials
			wantErr error
		}{
			{
				name: "unsupported credential type",
				creds: &enumeration.TaskCredentials{
					Type: "unsupported",
				},
				wantErr: fmt.Errorf("unsupported credential type: unsupported"),
			},
			{
				name: "invalid S3 credentials",
				creds: &enumeration.TaskCredentials{
					Type: enumeration.CredentialTypeS3,
					Values: map[string]any{
						"access_key": 123, // invalid type
					},
				},
				wantErr: fmt.Errorf("invalid S3 credentials"),
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := ToProtoCredentials(tc.creds)
				assert.IsType(t, tc.wantErr, err)
			})
		}
	})
}
