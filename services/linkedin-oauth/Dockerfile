# syntax=docker/dockerfile:1.7
FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY shared/ ./shared/
COPY services/linkedin-oauth/ ./services/linkedin-oauth/
ARG VERSION=dev
RUN cd services/linkedin-oauth && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -trimpath -o /out/linkedin-oauth .

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /
COPY --from=builder /out/linkedin-oauth /linkedin-oauth
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/linkedin-oauth"]
