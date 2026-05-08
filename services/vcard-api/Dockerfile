# syntax=docker/dockerfile:1.7
FROM golang:1.25-alpine AS builder
WORKDIR /src
# Copy only what this service needs. go.work is intentionally NOT copied —
# go build with a workspace requires every listed module to exist, but each
# Docker image only contains its own service + shared.
COPY shared/ ./shared/
COPY services/vcard-api/ ./services/vcard-api/
ARG VERSION=dev
RUN cd services/vcard-api && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -trimpath -o /out/vcard-api .

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /
COPY --from=builder /out/vcard-api /vcard-api
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/vcard-api"]
