# syntax=docker/dockerfile:1.7
FROM golang:1.22-alpine AS builder
WORKDIR /src
# Copy workspace + deps
COPY go.work go.work.sum* ./
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
