package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/aws/aws-lambda-go/lambda"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"plntir/core/internal/scanresultbroker"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	configuration, err := scanresultbroker.ConfigurationFromEnvironment()
	if err != nil {
		logger.Error("scan result broker configuration rejected")
		os.Exit(1)
	}
	awsConfiguration, err := awsconfig.LoadDefaultConfig(context.Background(), awsconfig.WithRegion("eu-central-1"))
	if err != nil {
		logger.Error("AWS SDK configuration failed")
		os.Exit(1)
	}
	handler, err := scanresultbroker.New(sqs.NewFromConfig(awsConfiguration), configuration, logger)
	if err != nil {
		logger.Error("scan result broker initialization failed")
		os.Exit(1)
	}
	lambda.Start(handler.Handle)
}
