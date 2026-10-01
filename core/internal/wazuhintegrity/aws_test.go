package wazuhintegrity

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/smithy-go"
)

func testAWSOptions() AWSRuntimeOptions {
	return AWSRuntimeOptions{
		Region: "eu-central-1", AccountID: "444455556666", Profile: "plntir-wazuh",
		ConfigPath:    "/etc/plntir/wazuh-aws.conf",
		RelayProxyURL: "http://10.23.0.7:3128",
		Bucket:        "plntir-wazuh-integrity-444455556666",
		KMSKeyARN:     "arn:aws:kms:eu-central-1:444455556666:key/00000000-0000-4000-8000-000000000000",
		TopicARN:      "arn:aws:sns:eu-central-1:444455556666:plntir-wazuh-independent-alerts",
	}
}

func TestAWSRuntimeOptionsRequireExactPrivateRelay(t *testing.T) {
	for _, value := range []string{"", "http://8.8.8.8:3128", "http://10.23.0.7:8080", "https://10.23.0.7:3128"} {
		options := testAWSOptions()
		options.RelayProxyURL = value
		if err := options.Validate(); err == nil {
			t.Fatalf("unsafe AWS relay proxy %q was accepted", value)
		}
	}
}

type fakeS3 struct {
	input  *s3.PutObjectInput
	output *s3.PutObjectOutput
	err    error
}

func (client *fakeS3) PutObject(_ context.Context, input *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	client.input = input
	return client.output, client.err
}

type fakeSNS struct {
	input  *sns.PublishInput
	output *sns.PublishOutput
	err    error
}

func (client *fakeSNS) Publish(_ context.Context, input *sns.PublishInput, _ ...func(*sns.Options)) (*sns.PublishOutput, error) {
	client.input = input
	return client.output, client.err
}

func TestS3ArchiveSinkBindsImmutablePutKMSAndChecksum(t *testing.T) {
	record, _ := NewRecord(1, [sha256.Size]byte{}, alertAtLevel(13), time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC))
	body, _ := record.Marshal()
	key, _ := record.ObjectKey()
	digest := sha256.Sum256(body)
	checksum := base64.StdEncoding.EncodeToString(digest[:])
	client := &fakeS3{output: &s3.PutObjectOutput{ChecksumSHA256: aws.String(checksum)}}
	err := (S3ArchiveSink{Client: client, Options: testAWSOptions()}).AppendRecord(context.Background(), key, body, record.EntryHash)
	if err != nil {
		t.Fatal(err)
	}
	input := client.input
	read, _ := io.ReadAll(input.Body)
	if string(read) != string(body) || aws.ToString(input.Bucket) != testAWSOptions().Bucket || aws.ToString(input.Key) != key {
		t.Fatal("S3 request changed the immutable record identity or body")
	}
	if aws.ToString(input.IfNoneMatch) != "*" || input.ServerSideEncryption != types.ServerSideEncryptionAwsKms || aws.ToString(input.SSEKMSKeyId) != testAWSOptions().KMSKeyARN {
		t.Fatal("S3 request is not conditional and KMS-bound")
	}
	if aws.ToString(input.ChecksumSHA256) != checksum || input.Metadata["plntir-entry-hash"] != record.EntryHash || aws.ToString(input.ExpectedBucketOwner) != testAWSOptions().AccountID {
		t.Fatal("S3 request lacks checksum, chain hash, or account binding")
	}
}

func TestS3PreconditionFailureIsIdempotentAlreadyArchived(t *testing.T) {
	record, _ := NewRecord(1, [sha256.Size]byte{}, alertAtLevel(10), time.Now())
	body, _ := record.Marshal()
	key, _ := record.ObjectKey()
	client := &fakeS3{err: &smithy.GenericAPIError{Code: "PreconditionFailed", Message: "exists"}}
	err := (S3ArchiveSink{Client: client, Options: testAWSOptions()}).AppendRecord(context.Background(), key, body, record.EntryHash)
	if !errors.Is(err, ErrAlreadyArchived) {
		t.Fatalf("conditional retry did not become idempotent: %v", err)
	}
}

func TestS3ArchiveRejectsTamperedBodyKeyAndMissingChecksum(t *testing.T) {
	record, _ := NewRecord(1, [sha256.Size]byte{}, alertAtLevel(10), time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC))
	body, _ := record.Marshal()
	key, _ := record.ObjectKey()
	for name, mutate := range map[string]func() (string, []byte, string){
		"body": func() (string, []byte, string) {
			return key, []byte(strings.Replace(string(body), "password=never-project-this", "password=changed", 1)), record.EntryHash
		},
		"key": func() (string, []byte, string) {
			return strings.Replace(key, "/04/", "/05/", 1), body, record.EntryHash
		},
		"entry hash": func() (string, []byte, string) {
			return key, body, strings.Repeat("A", 43)
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidateKey, candidateBody, candidateHash := mutate()
			client := &fakeS3{output: &s3.PutObjectOutput{}}
			err := (S3ArchiveSink{Client: client, Options: testAWSOptions()}).AppendRecord(context.Background(), candidateKey, candidateBody, candidateHash)
			if err == nil || client.input != nil {
				t.Fatalf("invalid record reached S3: %v", err)
			}
		})
	}
	client := &fakeS3{output: &s3.PutObjectOutput{}}
	if err := (S3ArchiveSink{Client: client, Options: testAWSOptions()}).AppendRecord(context.Background(), key, body, record.EntryHash); err == nil {
		t.Fatal("missing S3 checksum confirmation was accepted")
	}
}

func TestSNSAlertContainsOnlySanitizedProjection(t *testing.T) {
	record, _ := NewRecord(1, [sha256.Size]byte{}, alertAtLevel(13), time.Now())
	client := &fakeSNS{output: &sns.PublishOutput{MessageId: aws.String("message-1")}}
	err := (SNSAlertSink{Client: client, Options: testAWSOptions()}).PublishAlert(context.Background(), record.Summary)
	if err != nil {
		t.Fatal(err)
	}
	message := aws.ToString(client.input.Message)
	for _, forbidden := range []string{"password", "raw-only", "mac-secret-name", "description", "data"} {
		if strings.Contains(message, forbidden) {
			t.Fatalf("SNS message leaked raw field %q: %s", forbidden, message)
		}
	}
	var decoded map[string]any
	if json.Unmarshal([]byte(message), &decoded) != nil || len(decoded) != 7 || decoded["schema_version"] != float64(1) {
		t.Fatalf("SNS projection schema drifted: %s", message)
	}
}

type fakeCredentialProvider struct {
	value aws.Credentials
}

func (provider fakeCredentialProvider) Retrieve(context.Context) (aws.Credentials, error) {
	return provider.value, nil
}

func TestStrictCredentialsAcceptsOnlyExpiringProcessSession(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	valid := aws.Credentials{
		AccessKeyID: "ASIATEST", SecretAccessKey: "secret", SessionToken: "token",
		Source: "ProcessProvider", CanExpire: true, Expires: now.Add(time.Hour),
	}
	provider := strictProcessCredentials{Provider: fakeCredentialProvider{value: valid}, Now: func() time.Time { return now }}
	if _, err := provider.Retrieve(context.Background()); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*aws.Credentials){
		"static":      func(value *aws.Credentials) { value.CanExpire = false },
		"environment": func(value *aws.Credentials) { value.Source = "EnvConfigCredentials" },
		"long":        func(value *aws.Credentials) { value.Expires = now.Add(12 * time.Hour) },
		"no-token":    func(value *aws.Credentials) { value.SessionToken = "" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			provider := strictProcessCredentials{Provider: fakeCredentialProvider{value: candidate}, Now: func() time.Time { return now }}
			if _, err := provider.Retrieve(context.Background()); err == nil {
				t.Fatal("unsafe credential source was accepted")
			}
		})
	}
}
