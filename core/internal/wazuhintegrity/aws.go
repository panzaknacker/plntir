package wazuhintegrity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/smithy-go"
)

var (
	awsAccountPattern = regexp.MustCompile(`^[0-9]{12}$`)
	kmsKeyARNPattern  = regexp.MustCompile(`^arn:aws:kms:eu-central-1:([0-9]{12}):key/[0-9a-f-]{36}$`)
)

var ErrAlreadyArchived = errors.New("integrity object already exists")

type AWSRuntimeOptions struct {
	Region        string
	AccountID     string
	Profile       string
	ConfigPath    string
	RelayProxyURL string
	Bucket        string
	KMSKeyARN     string
	TopicARN      string
}

func (options AWSRuntimeOptions) Validate() error {
	if options.Region != "eu-central-1" || !awsAccountPattern.MatchString(options.AccountID) || options.Profile != "plntir-wazuh" {
		return errors.New("Wazuh AWS runtime identity, account, or region is invalid")
	}
	if options.Bucket != "plntir-wazuh-integrity-"+options.AccountID {
		return errors.New("Wazuh integrity bucket is not bound to the selected account")
	}
	matches := kmsKeyARNPattern.FindStringSubmatch(options.KMSKeyARN)
	if len(matches) != 2 || matches[1] != options.AccountID {
		return errors.New("Wazuh integrity KMS key is not bound to the selected account and region")
	}
	if options.TopicARN != "arn:aws:sns:eu-central-1:"+options.AccountID+":plntir-wazuh-independent-alerts" {
		return errors.New("Wazuh alert topic is not the exact isolated topic")
	}
	if !filepath.IsAbs(options.ConfigPath) || filepath.Clean(options.ConfigPath) != options.ConfigPath {
		return errors.New("Wazuh AWS config path must be clean and absolute")
	}
	if _, err := exactRelayProxy(options.RelayProxyURL); err != nil {
		return errors.New("Wazuh AWS runtime requires the exact private Relay proxy")
	}
	return nil
}

type s3PutObjectClient interface {
	PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error)
}

type snsPublishClient interface {
	Publish(context.Context, *sns.PublishInput, ...func(*sns.Options)) (*sns.PublishOutput, error)
}

type S3ArchiveSink struct {
	Client   s3PutObjectClient
	Options  AWSRuntimeOptions
	MaxBytes int
}

func (sink S3ArchiveSink) AppendRecord(ctx context.Context, key string, body []byte, entryHash string) error {
	if sink.Client == nil || sink.Options.Validate() != nil {
		return errors.New("S3 integrity sink is not sealed")
	}
	maximum := sink.MaxBytes
	if maximum <= 0 {
		maximum = MaximumAlertSize + (64 << 10)
	}
	if len(body) == 0 || len(body) > maximum || !strings.HasPrefix(key, "objects/") || strings.Contains(key, "..") {
		return errors.New("S3 integrity record is invalid or oversized")
	}
	if err := validateArchiveRecord(key, body, entryHash); err != nil {
		return err
	}
	digest := sha256.Sum256(body)
	contentLength := int64(len(body))
	output, err := sink.Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:              aws.String(sink.Options.Bucket),
		Key:                 aws.String(key),
		Body:                bytes.NewReader(body),
		ChecksumSHA256:      aws.String(base64.StdEncoding.EncodeToString(digest[:])),
		ContentLength:       aws.Int64(contentLength),
		ContentType:         aws.String("application/json"),
		ExpectedBucketOwner: aws.String(sink.Options.AccountID),
		IfNoneMatch:         aws.String("*"),
		Metadata: map[string]string{
			"plntir-entry-hash": entryHash,
			"plntir-schema":     "wazuh-record-v1",
		},
		ServerSideEncryption: types.ServerSideEncryptionAwsKms,
		SSEKMSKeyId:          aws.String(sink.Options.KMSKeyARN),
	})
	if err != nil {
		var apiError smithy.APIError
		if errors.As(err, &apiError) && (apiError.ErrorCode() == "PreconditionFailed" || apiError.ErrorCode() == "ConditionalRequestConflict") {
			return ErrAlreadyArchived
		}
		return fmt.Errorf("append Wazuh integrity object: %w", err)
	}
	if output == nil || aws.ToString(output.ChecksumSHA256) != base64.StdEncoding.EncodeToString(digest[:]) {
		return errors.New("S3 did not confirm the exact integrity object checksum")
	}
	return nil
}

func validateArchiveRecord(key string, body []byte, entryHash string) error {
	if _, err := decodeHash(entryHash); err != nil || !strings.HasSuffix(key, "-"+entryHash+".json") {
		return errors.New("S3 object key is not bound to the record hash")
	}
	var record Record
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil || ensureEOF(decoder) != nil || record.Validate() != nil {
		return errors.New("S3 integrity record body is invalid")
	}
	canonical, err := record.Marshal()
	if err != nil || !bytes.Equal(canonical, body) || record.EntryHash != entryHash {
		return errors.New("S3 integrity record body is not canonical or hash-bound")
	}
	expectedKey, err := record.ObjectKey()
	if err != nil || expectedKey != key {
		return errors.New("S3 integrity object key does not match its record")
	}
	return nil
}

type SNSAlertSink struct {
	Client  snsPublishClient
	Options AWSRuntimeOptions
}

func (sink SNSAlertSink) PublishAlert(ctx context.Context, summary AlertSummary) error {
	if sink.Client == nil || sink.Options.Validate() != nil {
		return errors.New("SNS Wazuh alert sink is not sealed")
	}
	if summary.RuleLevel < 0 || summary.RuleLevel > 16 || !ruleIDPattern.MatchString(summary.RuleID) {
		return errors.New("SNS Wazuh alert summary is invalid")
	}
	if summary.AgentID != "" && !agentIDPattern.MatchString(summary.AgentID) {
		return errors.New("SNS Wazuh alert agent is invalid")
	}
	if _, err := decodeHash(summary.EventSHA256); err != nil {
		return errors.New("SNS Wazuh alert event hash is invalid")
	}
	if _, err := time.Parse(time.RFC3339Nano, summary.OccurredAt); err != nil || severity(summary.RuleLevel) != summary.Severity {
		return errors.New("SNS Wazuh alert time or severity is invalid")
	}
	payload := struct {
		SchemaVersion int    `json:"schema_version"`
		EventSHA256   string `json:"event_sha256"`
		OccurredAt    string `json:"occurred_at"`
		RuleID        string `json:"rule_id"`
		RuleLevel     int    `json:"rule_level"`
		Severity      string `json:"severity"`
		AgentID       string `json:"agent_id,omitempty"`
	}{1, summary.EventSHA256, summary.OccurredAt, summary.RuleID, summary.RuleLevel, summary.Severity, summary.AgentID}
	message, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	result, err := sink.Client.Publish(ctx, &sns.PublishInput{
		TopicArn: aws.String(sink.Options.TopicARN),
		Subject:  aws.String("Plntir Wazuh security alert"),
		Message:  aws.String(string(message)),
	})
	if err != nil {
		return fmt.Errorf("publish independent Wazuh alert: %w", err)
	}
	if result == nil || result.MessageId == nil || *result.MessageId == "" {
		return errors.New("SNS accepted no Wazuh alert message ID")
	}
	return nil
}

type AWSRuntime struct {
	Archive S3ArchiveSink
	Alerts  SNSAlertSink
}

func LoadAWSRuntime(ctx context.Context, options AWSRuntimeOptions) (AWSRuntime, error) {
	if err := options.Validate(); err != nil {
		return AWSRuntime{}, err
	}
	if err := rejectAmbientAWSCredentials(); err != nil {
		return AWSRuntime{}, err
	}
	if err := requirePrivateConfig(options.ConfigPath); err != nil {
		return AWSRuntime{}, err
	}
	httpClient, err := newAWSRelayHTTPClient(options.RelayProxyURL)
	if err != nil {
		return AWSRuntime{}, err
	}
	configuration, err := awsconfig.LoadDefaultConfig(
		ctx,
		awsconfig.WithRegion(options.Region),
		awsconfig.WithSharedConfigProfile(options.Profile),
		awsconfig.WithSharedConfigFiles([]string{options.ConfigPath}),
		awsconfig.WithSharedCredentialsFiles([]string{"/dev/null"}),
		awsconfig.WithEC2IMDSClientEnableState(imds.ClientDisabled),
		awsconfig.WithHTTPClient(httpClient),
	)
	if err != nil {
		return AWSRuntime{}, fmt.Errorf("load Wazuh Roles Anywhere profile: %w", err)
	}
	configuration.Credentials = aws.NewCredentialsCache(strictProcessCredentials{
		Provider: configuration.Credentials,
		Now:      time.Now,
	})
	if _, err := configuration.Credentials.Retrieve(ctx); err != nil {
		return AWSRuntime{}, err
	}
	return AWSRuntime{
		Archive: S3ArchiveSink{Client: s3.NewFromConfig(configuration), Options: options},
		Alerts:  SNSAlertSink{Client: sns.NewFromConfig(configuration), Options: options},
	}, nil
}

type strictProcessCredentials struct {
	Provider aws.CredentialsProvider
	Now      func() time.Time
}

func (provider strictProcessCredentials) Retrieve(ctx context.Context) (aws.Credentials, error) {
	if provider.Provider == nil {
		return aws.Credentials{}, errors.New("Roles Anywhere process provider is missing")
	}
	credentials, err := provider.Provider.Retrieve(ctx)
	if err != nil {
		return aws.Credentials{}, err
	}
	now := time.Now().UTC()
	if provider.Now != nil {
		now = provider.Now().UTC()
	}
	if credentials.Source != "ProcessProvider" || !credentials.HasKeys() || credentials.SessionToken == "" || !credentials.CanExpire || !credentials.Expires.After(now) || credentials.Expires.After(now.Add(65*time.Minute)) {
		return aws.Credentials{}, errors.New("AWS credentials are not a short-lived Roles Anywhere process session")
	}
	return credentials, nil
}

func rejectAmbientAWSCredentials() error {
	for _, name := range []string{
		"AWS_ACCESS_KEY_ID",
		"AWS_SECRET_ACCESS_KEY",
		"AWS_SESSION_TOKEN",
		"AWS_WEB_IDENTITY_TOKEN_FILE",
		"AWS_CONTAINER_CREDENTIALS_FULL_URI",
		"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
		"AWS_SHARED_CREDENTIALS_FILE",
	} {
		if os.Getenv(name) != "" {
			return fmt.Errorf("ambient AWS credential source %s is forbidden", name)
		}
	}
	return nil
}

func requirePrivateConfig(path string) error {
	content, err := readPrivateFile(path, 64<<10)
	if err != nil {
		return fmt.Errorf("load Wazuh AWS config: %w", err)
	}
	if strings.Contains(string(content), "aws_access_key_id") || strings.Contains(string(content), "aws_secret_access_key") || !strings.Contains(string(content), "credential_process") {
		return errors.New("Wazuh AWS config must contain only a credential_process identity")
	}
	return nil
}
