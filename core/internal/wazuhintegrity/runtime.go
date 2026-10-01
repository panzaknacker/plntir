package wazuhintegrity

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"
)

type AnchorSink interface {
	PublishAnchor(context.Context, DailyAnchor) error
}

type Runtime struct {
	Journal        *Journal
	Archive        ArchiveSink
	Alerts         AlertSink
	Projections    ProjectionSink
	Anchors        AnchorSink
	SigningKey     ed25519.PrivateKey
	AlertThreshold int
}

func (runtime Runtime) Validate() error {
	if runtime.Journal == nil || runtime.Archive == nil || runtime.Alerts == nil || runtime.Projections == nil ||
		runtime.Anchors == nil || len(runtime.SigningKey) != ed25519.PrivateKeySize {
		return errors.New("Wazuh integrity runtime is not sealed")
	}
	if runtime.AlertThreshold < 0 || runtime.AlertThreshold > 16 {
		return errors.New("Wazuh alert threshold is invalid")
	}
	return nil
}

func (runtime Runtime) Ingest(ctx context.Context, raw []byte, receivedAt time.Time) (Record, error) {
	if err := runtime.Validate(); err != nil {
		return Record{}, err
	}
	item, err := runtime.Journal.Append(raw, receivedAt)
	if err != nil {
		return Record{}, err
	}
	if err := runtime.Drain(ctx); err != nil {
		return item.Record, fmt.Errorf("Wazuh alert is durable but delivery is pending: %w", err)
	}
	return item.Record, nil
}

func (runtime Runtime) Drain(ctx context.Context) error {
	if err := runtime.Validate(); err != nil {
		return err
	}
	runtime.Journal.deliveryMu.Lock()
	defer runtime.Journal.deliveryMu.Unlock()
	items, err := runtime.Journal.Pending()
	if err != nil {
		return err
	}
	projectionBlocked := false
	var failures []error
	for _, item := range items {
		archiveReady := runtime.deliverArchive(ctx, item, &failures)
		alertReady := runtime.deliverAlert(ctx, item, &failures)
		projectionReady := false
		if !projectionBlocked {
			projectionReady = runtime.deliverProjection(ctx, item, &failures)
			if !projectionReady {
				projectionBlocked = true
			}
		}
		if archiveReady && alertReady && projectionReady {
			if err := runtime.Journal.MarkDelivered(item.Record); err != nil {
				failures = append(failures, fmt.Errorf("complete record %d: %w", item.Record.Sequence, err))
			}
		}
	}
	return errors.Join(failures...)
}

func (runtime Runtime) PublishDailyAnchor(ctx context.Context, now time.Time) error {
	if err := runtime.Validate(); err != nil {
		return err
	}
	anchor, err := runtime.Journal.PrepareDailyAnchor(now, runtime.SigningKey)
	if err != nil {
		return err
	}
	return runtime.Anchors.PublishAnchor(ctx, anchor)
}

func (runtime Runtime) deliverArchive(ctx context.Context, item JournalItem, failures *[]error) bool {
	if ready, err := runtime.Journal.HasReceipt(item.Record, ArchiveReceipt); err != nil {
		*failures = append(*failures, fmt.Errorf("inspect archive receipt %d: %w", item.Record.Sequence, err))
		return false
	} else if ready {
		return true
	}
	key, err := item.Record.ObjectKey()
	if err == nil {
		err = runtime.Archive.AppendRecord(ctx, key, item.Body, item.Record.EntryHash)
	}
	if err != nil && !errors.Is(err, ErrAlreadyArchived) {
		*failures = append(*failures, fmt.Errorf("archive record %d: %w", item.Record.Sequence, err))
		return false
	}
	if err := runtime.Journal.MarkReceipt(item.Record, ArchiveReceipt); err != nil {
		*failures = append(*failures, fmt.Errorf("record archive receipt %d: %w", item.Record.Sequence, err))
		return false
	}
	return true
}

func (runtime Runtime) deliverAlert(ctx context.Context, item JournalItem, failures *[]error) bool {
	threshold := runtime.AlertThreshold
	if threshold == 0 {
		threshold = 12
	}
	if item.Record.Summary.RuleLevel < threshold {
		return true
	}
	if ready, err := runtime.Journal.HasReceipt(item.Record, AlertReceipt); err != nil {
		*failures = append(*failures, fmt.Errorf("inspect alert receipt %d: %w", item.Record.Sequence, err))
		return false
	} else if ready {
		return true
	}
	if err := runtime.Alerts.PublishAlert(ctx, item.Record.Summary); err != nil {
		*failures = append(*failures, fmt.Errorf("publish alert %d: %w", item.Record.Sequence, err))
		return false
	}
	if err := runtime.Journal.MarkReceipt(item.Record, AlertReceipt); err != nil {
		*failures = append(*failures, fmt.Errorf("record alert receipt %d: %w", item.Record.Sequence, err))
		return false
	}
	return true
}

func (runtime Runtime) deliverProjection(ctx context.Context, item JournalItem, failures *[]error) bool {
	if ready, err := runtime.Journal.HasReceipt(item.Record, ProjectionReceipt); err != nil {
		*failures = append(*failures, fmt.Errorf("inspect projection receipt %d: %w", item.Record.Sequence, err))
		return false
	} else if ready {
		return true
	}
	projection, err := ProjectionFromRecord(item.Record, mustParseTime(item.Record.ReceivedAt))
	if err == nil {
		err = runtime.Projections.PublishHealth(ctx, projection)
	}
	if err != nil {
		*failures = append(*failures, fmt.Errorf("publish projection %d: %w", item.Record.Sequence, err))
		return false
	}
	if err := runtime.Journal.MarkReceipt(item.Record, ProjectionReceipt); err != nil {
		*failures = append(*failures, fmt.Errorf("record projection receipt %d: %w", item.Record.Sequence, err))
		return false
	}
	return true
}
