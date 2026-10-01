FROM golang:1.24.7-alpine3.22@sha256:8aebdc2031bd790173104c00a69a5652658f9cfe14ae853a0264f2909d67fba7 AS build

WORKDIR /src
COPY go.mod ingress_proxy.go ingress_proxy_test.go public-routes-v4.89.2.json ./
RUN go test ./...
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -buildvcs=false -trimpath -ldflags='-s -w' \
    -o /out/plntir-fleet-ingress .

FROM scratch
COPY --from=build /out/plntir-fleet-ingress /usr/local/bin/plntir-fleet-ingress
USER 65532:65532
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/plntir-fleet-ingress", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/plntir-fleet-ingress"]
