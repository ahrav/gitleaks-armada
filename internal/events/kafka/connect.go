package kafka

import (
	"fmt"
	"time"

	"github.com/cenkalti/backoff"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
	"github.com/ahrav/gitleaks-armada/pkg/events"
)

// ConnectWithRetry attempts to establish a connection to Kafka with exponential backoff.
// It will retry failed connection attempts for up to 5 minutes, starting with 5 second intervals.
// This helps handle temporary network issues or Kafka cluster unavailability during startup.
func ConnectWithRetry(cfg *Config, logger *logger.Logger, metrics BrokerMetrics, tracer trace.Tracer) (events.Broker, error) {
	var broker events.Broker

	expBackoff := backoff.NewExponentialBackOff()
	expBackoff.MaxElapsedTime = 5 * time.Minute
	expBackoff.InitialInterval = 5 * time.Second

	operation := func() error {
		var err error
		broker, err = NewBroker(cfg, logger, metrics, tracer)
		if err != nil {
			return err
		}
		return nil
	}

	err := backoff.Retry(operation, expBackoff)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Kafka after retries: %w", err)
	}

	return broker, nil
}
