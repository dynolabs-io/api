# syntax=docker/dockerfile:1.7
FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY shared/ ./shared/
COPY services/web-profile/ ./services/web-profile/
ARG VERSION=dev
RUN cd services/web-profile && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -trimpath -o /out/web-profile .

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /
COPY --from=builder /out/web-profile /web-profile
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/web-profile"]
