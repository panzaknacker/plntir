.PHONY: plntirctl plntir-web plntir-core plntir-kms-broker plntir-scan-result-broker lambda-artifacts test test-race check scanner-check wazuh-anchor-check web-check mdm-check archive-check iac-check platform-check clean

plntirctl:
	mkdir -p bin
	cd client && CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags '-s -w' -o ../bin/plntirctl ./cmd/plntirctl

plntir-web:
	mkdir -p bin
	cd client && CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags '-s -w' -o ../bin/plntir-web ./cmd/plntir-web

plntir-core:
	mkdir -p bin
	cd core && CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags '-s -w' -o ../bin/plntir-core ./cmd/plntir-core

plntir-kms-broker:
	mkdir -p bin
	cd core && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -tags lambda.norpc -buildvcs=false -trimpath -ldflags '-s -w' -o ../bin/plntir-kms-broker-arm64 ./cmd/plntir-kms-broker

plntir-scan-result-broker:
	mkdir -p bin
	cd core && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -tags lambda.norpc -buildvcs=false -trimpath -ldflags '-s -w' -o ../bin/plntir-scan-result-broker-arm64 ./cmd/plntir-scan-result-broker

lambda-artifacts: plntir-kms-broker plntir-scan-result-broker
	cd core && go run ./cmd/plntir-lambda-pack -input ../bin/plntir-kms-broker-arm64 -output ../bin/plntir-kms-broker-arm64.zip
	cd core && go run ./cmd/plntir-lambda-pack -input ../bin/plntir-scan-result-broker-arm64 -output ../bin/plntir-scan-result-broker-arm64.zip
	sha256sum bin/plntir-kms-broker-arm64.zip bin/plntir-scan-result-broker-arm64.zip

test:
	cd client && go test ./...
	cd core && go test ./...
	cd mac/archive-agent && go test ./...

test-race:
	cd client && go test -race ./...
	cd core && go test -race ./...
	cd mac/archive-agent && go test -race ./...

check:
	cd client && go test ./...
	cd client && go vet ./...
	cd core && go test ./...
	cd core && go vet ./...
	./tests/openapi-contract-checks.py
	python3 ./tests/fleet-ingress-checks.py
	bash ./tests/required-tools-checks.sh
	python3 ./tests/readiness-disabled-checks.py
	./tests/static-checks.sh
	./tests/dscl-output-checks.sh
	./tests/integrity-checks.sh
	./tests/offhost-backup-checks.sh
	./tests/web-dashboard-checks.sh
	./tests/package-build-checks.sh

scanner-check:
	cd cloudflare/scanner && npm run check
	cd cloudflare/scanner/container && go test ./...

wazuh-anchor-check:
	cd cloudflare/wazuh-anchor && npm run check

web-check:
	cd web && npm run check
	cd web && npm run build

mdm-check:
	python3 mdm/fleet/ingress_policy.py --check
	python3 tests/fleet-ingress-checks.py
	cd mdm/fleet && go test ./...
	cd mdm/fleet && go vet ./...

archive-check:
	cd mac/archive-agent && go test -count=1 ./...
	cd mac/archive-agent && go vet ./...
	cd mac/archive-agent && GOOS=darwin GOARCH=arm64 go build ./...
	cd mac/archive-agent && GOOS=darwin GOARCH=amd64 go build ./...

iac-check:
	./infra/bootstrap/validate.sh --local-only
	./infra/terraform/validate.sh
	./infra/ansible/validate.sh
	./tests/lightsail-network-seal-checks.sh

platform-check: check scanner-check wazuh-anchor-check web-check mdm-check archive-check iac-check
	cd core && go test -race ./...
	cd cloudflare/scanner/container && go test -race ./...
	cd mdm/fleet && go test -race ./...

clean:
	rm -f bin/plntirctl bin/plntir-web bin/plntir-core bin/plntir-kms-broker-arm64 bin/plntir-scan-result-broker-arm64 bin/plntir-kms-broker-arm64.zip bin/plntir-scan-result-broker-arm64.zip
