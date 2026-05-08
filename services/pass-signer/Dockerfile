# syntax=docker/dockerfile:1.7
FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY shared/ ./shared/
COPY services/pass-signer/ ./services/pass-signer/
ARG VERSION=dev
RUN cd services/pass-signer && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -trimpath -o /out/pass-signer .

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /
COPY --from=builder /out/pass-signer /pass-signer
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/pass-signer"]
