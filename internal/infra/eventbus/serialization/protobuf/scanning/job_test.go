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
		auth := scanning.NewAuth(
			string(scanning.AuthTypeToken),
			map[string]any{
				"token": "test-token",
				"url":   "https://api.github.com",
			},
		)

		targetSpec := scanning.NewTarget(
			"test-target",
			shared.SourceTypeGitHub,
			&auth,
			map[string]string{
				"key": "value",
			},
		)

		domainEvent := scanning.NewJobCreatedEvent(jobID, targetSpec)

		// Test domain to proto conversion.
		protoEvent, err := JobCreatedEventToProto(domainEvent)
		require.NoError(t, err)
		assert.Equal(t, jobID, protoEvent.JobId)
		assert.Equal(t, targetSpec.Name(), protoEvent.TargetSpec.Name)
		assert.Equal(t, pb.SourceType_SOURCE_TYPE_GITHUB, protoEvent.TargetSpec.SourceType)
		assert.Equal(t, string(auth.Type()), protoEvent.TargetSpec.Auth.Type)

		// Test proto to domain conversion.
		convertedEvent, err := ProtoToJobCreatedEvent(protoEvent)
		require.NoError(t, err)
		assert.Equal(t, jobID, convertedEvent.JobID)
		assert.Equal(t, targetSpec.Name(), convertedEvent.Target.Name())
		assert.Equal(t, targetSpec.SourceType(), convertedEvent.Target.SourceType())
		require.True(t, convertedEvent.Target.HasAuth())
		assert.Equal(t, auth.Type(), convertedEvent.Target.Auth().Type())
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
			map[string]string{
				"key": "value",
			},
		)

		domainEvent := scanning.NewJobRequestedEvent(
			[]scanning.Target{target},
			"test-user",
		)

		// Test domain to proto conversion
		protoEvent, err := JobRequestedEventToProto(domainEvent)
		require.NoError(t, err)
		assert.Equal(t, domainEvent.RequestedBy, protoEvent.RequestedBy)
		require.Len(t, protoEvent.Targets, 1)
		assert.Equal(t, target.Name(), protoEvent.Targets[0].Name)
		assert.Equal(t, pb.SourceType_SOURCE_TYPE_GITHUB, protoEvent.Targets[0].SourceType)
		assert.Equal(t, string(auth.Type()), protoEvent.Targets[0].Auth.Type)

		// Test proto to domain conversion
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
					EventId:     uuid.New().String(),
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
