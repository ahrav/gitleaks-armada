package scanning

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
	serializationerrors "github.com/ahrav/gitleaks-armada/internal/infra/eventbus/serialization/errors"
	pb "github.com/ahrav/gitleaks-armada/proto"
)

func TestJobCreatedEventConversion(t *testing.T) {
	t.Run("successful conversions", func(t *testing.T) {
		job := scanning.NewJob()
		auth := scanning.NewAuth(
			string(scanning.AuthTypeToken),
			map[string]any{
				"token": "test-token",
				"url":   "https://api.github.com",
			},
		)

		metadata := map[string]string{
			"environment": "production",
			"team":        "security",
		}

		targetSpec := scanning.NewTarget(
			"test-target",
			shared.SourceTypeGitHub,
			&auth,
			metadata,
			scanning.TargetConfig{
				GitHub: scanning.NewGitHubTarget(
					"test-org",
					[]string{"repo-1", "repo-2"},
				),
			},
		)

		domainEvent := scanning.NewJobCreatedEvent(job, targetSpec)

		// Test domain to proto conversion.
		protoEvent, err := JobCreatedEventToProto(domainEvent)
		require.NoError(t, err)
		assert.Equal(t, job.JobID().String(), protoEvent.JobId)
		assert.Equal(t, targetSpec.Name(), protoEvent.TargetSpec.Name)
		assert.Equal(t, pb.SourceType_SOURCE_TYPE_GITHUB, protoEvent.TargetSpec.SourceType)
		assert.Equal(t, string(auth.Type()), protoEvent.TargetSpec.Auth.Type)
		assert.Equal(t, metadata, protoEvent.TargetSpec.Metadata)

		// Verify GitHub-specific fields.
		githubTarget := protoEvent.TargetSpec.GetGithub()
		require.NotNil(t, githubTarget)
		assert.Equal(t, "test-org", githubTarget.Org)
		assert.Equal(t, []string{"repo-1", "repo-2"}, githubTarget.RepoList)
		// TODO: Additional specific fields.

		// Test proto to domain conversion.
		convertedEvent, err := ProtoToJobCreatedEvent(protoEvent)
		require.NoError(t, err)
		assert.Equal(t, job.JobID().String(), convertedEvent.Job.JobID().String())
		assert.Equal(t, targetSpec.Name(), convertedEvent.Target.Name())
		assert.Equal(t, targetSpec.SourceType(), convertedEvent.Target.SourceType())
		assert.Equal(t, metadata, convertedEvent.Target.Metadata())
		require.True(t, convertedEvent.Target.HasAuth())
		assert.Equal(t, auth.Type(), convertedEvent.Target.Auth().Type())

		// Verify converted GitHub target.
		convertedGitHub := convertedEvent.Target.GitHub()
		require.NotNil(t, convertedGitHub)
		assert.Equal(t, "test-org", convertedGitHub.Org())
		assert.Equal(t, []string{"repo-1", "repo-2"}, convertedGitHub.RepoList())
	})

	t.Run("S3 target conversion", func(t *testing.T) {
		job := scanning.NewJob()
		metadata := map[string]string{
			"region":     "us-west-2",
			"department": "engineering",
		}

		targetSpec := scanning.NewTarget(
			"s3-target",
			shared.SourceTypeS3,
			nil, // No auth for this test
			metadata,
			scanning.TargetConfig{
				S3: scanning.NewS3Target(
					"test-bucket",
					"path/prefix",
					"us-west-2",
				),
			},
		)

		domainEvent := scanning.NewJobCreatedEvent(job, targetSpec)

		// Test domain to proto conversion.
		protoEvent, err := JobCreatedEventToProto(domainEvent)
		require.NoError(t, err)
		assert.Equal(t, metadata, protoEvent.TargetSpec.Metadata)

		s3Target := protoEvent.TargetSpec.GetS3()
		require.NotNil(t, s3Target)
		assert.Equal(t, "test-bucket", s3Target.Bucket)
		assert.Equal(t, "path/prefix", s3Target.Prefix)
		assert.Equal(t, "us-west-2", s3Target.Region)

		// Test proto to domain conversion.
		convertedEvent, err := ProtoToJobCreatedEvent(protoEvent)
		require.NoError(t, err)
		assert.Equal(t, metadata, convertedEvent.Target.Metadata())

		convertedS3 := convertedEvent.Target.S3()
		require.NotNil(t, convertedS3)
		assert.Equal(t, "test-bucket", convertedS3.Bucket())
		assert.Equal(t, "path/prefix", convertedS3.Prefix())
		assert.Equal(t, "us-west-2", convertedS3.Region())
	})

	t.Run("URL target conversion", func(t *testing.T) {
		job := scanning.NewJob()
		metadata := map[string]string{
			"scan_type": "web",
			"priority":  "high",
		}

		targetSpec := scanning.NewTarget(
			"url-target",
			shared.SourceTypeURL,
			nil,
			metadata,
			scanning.TargetConfig{
				URL: scanning.NewURLTarget(
					[]string{"https://example.com", "https://test.com"},
				),
			},
		)

		domainEvent := scanning.NewJobCreatedEvent(job, targetSpec)

		// Test domain to proto conversion.
		protoEvent, err := JobCreatedEventToProto(domainEvent)
		require.NoError(t, err)
		assert.Equal(t, metadata, protoEvent.TargetSpec.Metadata)

		urlTarget := protoEvent.TargetSpec.GetUrl()
		require.NotNil(t, urlTarget)
		assert.Equal(t, []string{"https://example.com", "https://test.com"}, urlTarget.Urls)

		// Test proto to domain conversion.
		convertedEvent, err := ProtoToJobCreatedEvent(protoEvent)
		require.NoError(t, err)
		assert.Equal(t, metadata, convertedEvent.Target.Metadata())

		convertedURL := convertedEvent.Target.URL()
		require.NotNil(t, convertedURL)
		assert.Equal(t, []string{"https://example.com", "https://test.com"}, convertedURL.URLs())
	})

	t.Run("error cases", func(t *testing.T) {
		testCases := []struct {
			name    string
			event   *pb.JobCreatedEvent
			wantErr error
		}{
			{
				name:    "nil event",
				event:   nil,
				wantErr: serializationerrors.ErrNilEvent{EventType: "JobCreatedEvent"},
			},
			{
				name: "nil target spec",
				event: &pb.JobCreatedEvent{
					JobId:      uuid.New().String(),
					TargetSpec: nil,
				},
				wantErr: serializationerrors.ErrNilEvent{EventType: "JobCreatedEvent"},
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := ProtoToJobCreatedEvent(tc.event)
				assert.IsType(t, tc.wantErr, err)
			})
		}
	})
}

func TestJobRequestedEventConversion(t *testing.T) {
	t.Run("successful conversions", func(t *testing.T) {
		auth := scanning.NewAuth(
			string(scanning.AuthTypeToken),
			map[string]any{
				"token": "test-token",
				"url":   "https://api.github.com",
			},
		)

		target := scanning.NewTarget(
			"test-target",
			shared.SourceTypeGitHub,
			&auth,
			map[string]string{},
			scanning.TargetConfig{
				GitHub: scanning.NewGitHubTarget("test-org", []string{"test-repo"}),
			},
		)

		domainEvent := scanning.NewJobRequestedEvent(
			uuid.New(),
			[]scanning.Target{target},
			"test-user",
		)

		// Test domain to proto conversion.
		protoEvent, err := JobRequestedEventToProto(domainEvent)
		require.NoError(t, err)
		assert.Equal(t, domainEvent.RequestedBy, protoEvent.RequestedBy)
		require.Len(t, protoEvent.Targets, 1)
		assert.Equal(t, target.Name(), protoEvent.Targets[0].Name)
		assert.Equal(t, pb.SourceType_SOURCE_TYPE_GITHUB, protoEvent.Targets[0].SourceType)
		assert.Equal(t, string(auth.Type()), protoEvent.Targets[0].Auth.Type)

		// Test proto to domain conversion.
		convertedEvent, err := ProtoToJobRequestedEvent(protoEvent)
		require.NoError(t, err)
		assert.Equal(t, domainEvent.RequestedBy, convertedEvent.RequestedBy)
		require.Len(t, convertedEvent.Targets, 1)
		assert.Equal(t, target.Name(), convertedEvent.Targets[0].Name())
		assert.Equal(t, target.SourceType(), convertedEvent.Targets[0].SourceType())
		require.True(t, convertedEvent.Targets[0].HasAuth())
		assert.Equal(t, auth.Type(), convertedEvent.Targets[0].Auth().Type())
	})

	t.Run("error cases", func(t *testing.T) {
		testCases := []struct {
			name    string
			event   *pb.JobRequestedEvent
			wantErr error
		}{
			{
				name:    "nil event",
				event:   nil,
				wantErr: serializationerrors.ErrNilEvent{EventType: "JobRequestedEvent"},
			},
			{
				name: "empty targets",
				event: &pb.JobRequestedEvent{
					JobId:       uuid.New().String(),
					Targets:     nil,
					RequestedBy: "test-user",
				},
				wantErr: serializationerrors.ErrNilEvent{EventType: "JobRequestedEvent"},
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := ProtoToJobRequestedEvent(tc.event)
				assert.IsType(t, tc.wantErr, err)
			})
		}
	})
}

func TestJobEnumerationCompletedEventConversion(t *testing.T) {
	t.Run("successful conversion", func(t *testing.T) {
		jobID := uuid.New()
		totalTasks := 10
		domainEvent := scanning.NewJobEnumerationCompletedEvent(jobID, totalTasks)

		// Task the domain event to proto.
		protoEvent := JobEnumerationCompletedEventToProto(domainEvent)
		require.NotNil(t, protoEvent)
		assert.Equal(t, jobID.String(), protoEvent.JobId)
		assert.Equal(t, int32(totalTasks), protoEvent.TotalTasks)
		assert.Equal(t, domainEvent.OccurredAt().UnixNano(), protoEvent.Timestamp)

		// Convert the proto event back to the domain event.
		convertedEvent, err := ProtoToJobEnumerationCompletedEvent(protoEvent)
		require.NoError(t, err)
		assert.Equal(t, jobID, convertedEvent.JobID)
		assert.Equal(t, totalTasks, convertedEvent.TotalTasks)
	})

	t.Run("nil event", func(t *testing.T) {
		_, err := ProtoToJobEnumerationCompletedEvent(nil)
		require.Error(t, err)
		assert.IsType(t, serializationerrors.ErrNilEvent{}, err)
	})

	t.Run("invalid job id", func(t *testing.T) {
		protoEvent := &pb.JobEnumerationCompletedEvent{
			JobId:      "invalid-uuid",
			Timestamp:  0,
			TotalTasks: 5,
		}
		_, err := ProtoToJobEnumerationCompletedEvent(protoEvent)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parse job ID")
	})
}
