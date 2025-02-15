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
		jobID := uuid.New().String()
		targetSpec := scanning.NewTarget(
			"test-target",
			shared.SourceTypeGitHub,
			"auth-ref",
			map[string]string{
				"key": "value",
			},
		)
		authConfig := scanning.NewAuth(
			"github",
			map[string]any{
				"token": "test-token",
				"url":   "https://api.github.com",
			},
		)

		domainEvent := scanning.NewJobCreatedEvent(jobID, targetSpec, authConfig)

		// Test domain to proto conversion.
		protoEvent, err := JobCreatedEventToProto(domainEvent)
		require.NoError(t, err)
		assert.Equal(t, jobID, protoEvent.JobId)
		assert.Equal(t, targetSpec.Name(), protoEvent.TargetSpec.Name)
		assert.Equal(t, pb.SourceType_SOURCE_TYPE_GITHUB, protoEvent.TargetSpec.SourceType)
		assert.Equal(t, authConfig.Type(), protoEvent.AuthConfig.Type)

		// Test proto to domain conversion.
		convertedEvent, err := ProtoToJobCreatedEvent(protoEvent)
		require.NoError(t, err)
		assert.Equal(t, jobID, convertedEvent.JobID)
		assert.Equal(t, targetSpec.Name(), convertedEvent.Target.Name())
		assert.Equal(t, targetSpec.SourceType(), convertedEvent.Target.SourceType())
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
				wantErr: serializationerrors.ErrNilEvent{EventType: "JobCreated"},
			},
			{
				name: "nil target spec",
				event: &pb.JobCreatedEvent{
					JobId:      uuid.New().String(),
					TargetSpec: nil,
					AuthConfig: &pb.AuthConfig{Type: "test"},
				},
				wantErr: serializationerrors.ErrNilEvent{EventType: "TargetSpec"},
			},
			{
				name: "nil auth config",
				event: &pb.JobCreatedEvent{
					JobId: uuid.New().String(),
					TargetSpec: &pb.TargetSpec{
						Name:       "test",
						SourceType: pb.SourceType_SOURCE_TYPE_GITHUB,
					},
					AuthConfig: nil,
				},
				wantErr: serializationerrors.ErrNilEvent{EventType: "AuthConfig"},
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
