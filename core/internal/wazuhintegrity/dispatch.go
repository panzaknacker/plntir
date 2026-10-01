package wazuhintegrity

import (
	"context"
	"errors"
	"fmt"
)

type ArchiveSink interface {
	AppendRecord(context.Context, string, []byte, string) error
}

type AlertSink interface {
	PublishAlert(context.Context, AlertSummary) error
}

type ProjectionSink interface {
	PublishHealth(context.Context, HealthProjection) error
}

type Dispatcher struct {
	Archive        ArchiveSink
	Alerts         AlertSink
	Projections    ProjectionSink
	AlertThreshold int
}

func (dispatcher Dispatcher) Deliver(ctx context.Context, record Record) error {
	if dispatcher.Archive == nil || dispatcher.Alerts == nil || dispatcher.Projections == nil {
		return errors.New("all independent Wazuh sinks are required")
	}
	body, err := record.Marshal()
	if err != nil {
		return err
	}
	key, err := record.ObjectKey()
	if err != nil {
		return err
	}
	projection, err := ProjectionFromRecord(record, mustParseTime(record.ReceivedAt))
	if err != nil {
		return err
	}
	var failures []error
	if err := dispatcher.Archive.AppendRecord(ctx, key, body, record.EntryHash); err != nil {
		failures = append(failures, fmt.Errorf("append integrity record: %w", err))
	}
	threshold := dispatcher.AlertThreshold
	if threshold <= 0 {
		threshold = 12
	}
	if record.Summary.RuleLevel >= threshold {
		if err := dispatcher.Alerts.PublishAlert(ctx, record.Summary); err != nil {
			failures = append(failures, fmt.Errorf("publish independent alert: %w", err))
		}
	}
	if err := dispatcher.Projections.PublishHealth(ctx, projection); err != nil {
		failures = append(failures, fmt.Errorf("publish sanitized health: %w", err))
	}
	return errors.Join(failures...)
}
