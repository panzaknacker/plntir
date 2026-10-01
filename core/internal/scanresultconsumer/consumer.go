package scanresultconsumer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"regexp"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"plntir/core/internal/envelope"
)

const (
	maximumMessageBytes = 32 << 10
	maximumBatchSize    = 10
	longPollSeconds     = 20
	visibilitySeconds   = 120
)

var accountID = regexp.MustCompile(`^[0-9]{12}$`)

type QueueAPI interface {
	ReceiveMessage(context.Context, *sqs.ReceiveMessageInput, ...func(*sqs.Options)) (*sqs.ReceiveMessageOutput, error)
	DeleteMessage(context.Context, *sqs.DeleteMessageInput, ...func(*sqs.Options)) (*sqs.DeleteMessageOutput, error)
}

type ResultStore interface {
	IngestSignedScanResult(context.Context, envelope.Envelope, ed25519.PublicKey, time.Time) (bool, error)
}

type Configuration struct {
	AWSAccountID     string
	QueueURL         string
	ScannerVerifyKey ed25519.PublicKey
}

func (configuration Configuration) Validate() error {
	if !accountID.MatchString(configuration.AWSAccountID) {
		return errors.New("AWS account binding is invalid")
	}
	if len(configuration.ScannerVerifyKey) != ed25519.PublicKeySize {
		return errors.New("scanner result verification key is invalid")
	}
	queueURL, err := url.Parse(configuration.QueueURL)
	wantedPath := "/" + configuration.AWSAccountID + "/plntir-scan-results.fifo"
	if err != nil || queueURL.Scheme != "https" || queueURL.Host != "sqs.eu-central-1.amazonaws.com" ||
		queueURL.Path != wantedPath || queueURL.RawQuery != "" || queueURL.Fragment != "" || queueURL.User != nil {
		return errors.New("scan result queue URL is not the bound eu-central-1 FIFO queue")
	}
	return nil
}

type Consumer struct {
	queue  QueueAPI
	store  ResultStore
	config Configuration
	now    func() time.Time
	logger *slog.Logger
}

type PollResult struct {
	Received   int
	Committed  int
	Duplicates int
	Rejected   int
}

func New(queue QueueAPI, store ResultStore, configuration Configuration, logger *slog.Logger) (*Consumer, error) {
	if queue == nil || store == nil {
		return nil, errors.New("SQS client and result store are required")
	}
	if err := configuration.Validate(); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	return &Consumer{queue: queue, store: store, config: configuration, now: time.Now, logger: logger}, nil
}

// PollOnce long-polls one bounded batch. a message is deleted only after the
// signed result has committed, or the store proves that the exact result was
// already committed. invalid and transiently failing messages remain for SQS
// redrive to the DLQ.
func (consumer *Consumer) PollOnce(ctx context.Context) (PollResult, error) {
	output, err := consumer.queue.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{
		QueueUrl:            aws.String(consumer.config.QueueURL),
		MaxNumberOfMessages: maximumBatchSize,
		WaitTimeSeconds:     longPollSeconds,
		VisibilityTimeout:   visibilitySeconds,
	})
	if err != nil {
		return PollResult{}, fmt.Errorf("receive scan results: %w", err)
	}
	if output == nil {
		return PollResult{}, errors.New("receive scan results returned no response")
	}
	result := PollResult{Received: len(output.Messages)}
	var failures []error
	for index := range output.Messages {
		duplicate, err := consumer.processMessage(ctx, aws.ToString(output.Messages[index].Body), aws.ToString(output.Messages[index].ReceiptHandle))
		if err != nil {
			result.Rejected++
			failures = append(failures, fmt.Errorf("message %d: %w", index+1, err))
			continue
		}
		result.Committed++
		if duplicate {
			result.Duplicates++
		}
	}
	return result, errors.Join(failures...)
}

func (consumer *Consumer) processMessage(ctx context.Context, body, receiptHandle string) (bool, error) {
	if len(body) == 0 || len(body) > maximumMessageBytes {
		return false, errors.New("message body is empty or oversized")
	}
	if len(receiptHandle) == 0 || len(receiptHandle) > 4096 {
		return false, errors.New("message receipt handle is invalid")
	}
	var value envelope.Envelope
	decoder := json.NewDecoder(bytes.NewBufferString(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return false, errors.New("message envelope is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return false, errors.New("message envelope has trailing data")
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(canonical, []byte(body)) {
		return false, errors.New("message envelope is not canonical")
	}
	duplicate, err := consumer.store.IngestSignedScanResult(ctx, value, consumer.config.ScannerVerifyKey, consumer.now().UTC())
	if err != nil {
		return false, fmt.Errorf("commit signed result: %w", err)
	}
	if _, err := consumer.queue.DeleteMessage(ctx, &sqs.DeleteMessageInput{
		QueueUrl:      aws.String(consumer.config.QueueURL),
		ReceiptHandle: aws.String(receiptHandle),
	}); err != nil {
		return false, fmt.Errorf("acknowledge committed result: %w", err)
	}
	return duplicate, nil
}

// Run keeps polling until cancellation. it never logs message bodies or scan
// metadata; detailed security failures are retained in SQS/DLQ and core audit.
func (consumer *Consumer) Run(ctx context.Context) error {
	for ctx.Err() == nil {
		result, err := consumer.PollOnce(ctx)
		if err == nil {
			continue
		}
		if ctx.Err() != nil {
			break
		}
		consumer.logger.Warn("scan result poll failed", "received", result.Received, "rejected", result.Rejected)
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
		case <-timer.C:
		}
	}
	return ctx.Err()
}
