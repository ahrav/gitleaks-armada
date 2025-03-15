package handlers

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/rules"
)

// Mock implementations for testing.
type mockRulesService struct{ mock.Mock }

func (m *mockRulesService) SaveRule(ctx context.Context, r rules.GitleaksRule) error {
	return m.Called(ctx, r).Error(0)
}

func (m *mockRulesService) CompleteRulePublishing(ctx context.Context) error {
	return m.Called(ctx).Error(0)
}

// setupRulesHandlerTestSuite creates a RulesHandler with mock dependencies for testing.
func setupRulesHandlerTestSuite() (*RulesHandler, *mockRulesService) {
	mockRulesSvc := new(mockRulesService)
	tracer := noop.NewTracerProvider().Tracer("test-tracer")
	handler := NewRulesHandler("test-controller", mockRulesSvc, tracer)
	return handler, mockRulesSvc
}

func TestHandleRule(t *testing.T) {
	rule := rules.GitleaksRule{
		RuleID:      "test-rule",
		Description: "Test rule for unit tests",
		Regex:       "test-regex",
	}

	ruleMsg := rules.GitleaksRuleMessage{GitleaksRule: rule, Hash: "test-hash"}
	ruleEvt := rules.NewRuleUpdatedEvent(ruleMsg)

	tests := []struct {
		name              string
		setupMock         func(m *mockRulesService)
		expectErr         bool
		expectedErrSubstr string
	}{
		{
			name: "success",
			setupMock: func(m *mockRulesService) {
				m.On("SaveRule", mock.Anything, rule).Return(nil)
			},
			expectErr: false,
		},
		{
			name: "save rule error",
			setupMock: func(m *mockRulesService) {
				m.On("SaveRule", mock.Anything, rule).Return(errors.New("save error"))
			},
			expectErr:         true,
			expectedErrSubstr: "failed to persist rule",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, mockRulesSvc := setupRulesHandlerTestSuite()
			tt.setupMock(mockRulesSvc)

			var ackCalled bool
			ack := func(err error) { ackCalled = true }

			evt := events.EventEnvelope{
				Type:    rules.EventTypeRulesUpdated,
				Payload: ruleEvt,
				Metadata: events.EventMetadata{
					Partition: 1,
					Offset:    100,
				},
			}

			err := handler.HandleRule(context.Background(), evt, ack)
			if tt.expectErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErrSubstr)
			} else {
				assert.NoError(t, err)
			}
			assert.True(t, ackCalled, "ack function should have been called")
			mockRulesSvc.AssertExpectations(t)
		})
	}
}

func TestHandleRulesPublished(t *testing.T) {
	publishedEvt := rules.NewRulePublishingCompletedEvent()

	tests := []struct {
		name              string
		setupMock         func(m *mockRulesService)
		expectErr         bool
		expectedErrSubstr string
	}{
		{
			name:      "success",
			setupMock: func(m *mockRulesService) {},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, mockRulesSvc := setupRulesHandlerTestSuite()
			tt.setupMock(mockRulesSvc)

			var ackCalled bool
			ack := func(err error) { ackCalled = true }

			evt := events.EventEnvelope{Type: rules.EventTypeRulesPublished, Payload: publishedEvt}
			err := handler.HandleRulesPublished(context.Background(), evt, ack)
			if tt.expectErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErrSubstr)
			} else {
				assert.NoError(t, err)
			}
			assert.True(t, ackCalled, "ack function should have been called")
			mockRulesSvc.AssertExpectations(t)
		})
	}
}

// TestRulesHandlerSupportedEvents verifies that the RulesHandler reports all expected event types.
// This prevents event type handling regressions when new events are added but not properly registered.
func TestRulesHandlerSupportedEvents(t *testing.T) {
	handler, _ := setupRulesHandlerTestSuite()

	expectedEventTypes := []events.EventType{
		rules.EventTypeRulesUpdated,
		rules.EventTypeRulesPublished,
	}

	supportedEvents := handler.SupportedEvents()

	assert.Len(t, supportedEvents, len(expectedEventTypes),
		"Handler should support exactly %d event types", len(expectedEventTypes))

	for _, expected := range expectedEventTypes {
		assert.Contains(t, supportedEvents, expected,
			"Handler should support the %s event type", expected)
	}
}
