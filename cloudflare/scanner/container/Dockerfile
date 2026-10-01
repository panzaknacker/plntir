FROM golang:1.24.7-alpine3.22 AS build

WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/plntir-scanner ./cmd/plntir-scanner

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/plntir-scanner /usr/local/bin/plntir-scanner
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/plntir-scanner"]
