package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/aws/aws-lambda-go/lambda"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"

	"plntir/core/internal/kmsbroker"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	configuration, err := kmsbroker.ConfigurationFromEnvironment()
	if err != nil {
		logger.Error("KMS broker configuration rejected")
		os.Exit(1)
	}
	awsConfiguration, err := awsconfig.LoadDefaultConfig(context.Background(), awsconfig.WithRegion("eu-central-1"))
	if err != nil {
		logger.Error("AWS SDK configuration failed")
		os.Exit(1)
	}
	handler, err := kmsbroker.New(kms.NewFromConfig(awsConfiguration), configuration, logger)
	if err != nil {
		logger.Error("KMS broker initialization failed")
		os.Exit(1)
	}
	lambda.Start(handler.Handle)
}
