# syntax=docker/dockerfile:1.7
FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY shared/ ./shared/
COPY services/photo-cdn/ ./services/photo-cdn/
ARG VERSION=dev
RUN cd services/photo-cdn && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -trimpath -o /out/photo-cdn .

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /
COPY --from=builder /out/photo-cdn /photo-cdn
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/photo-cdn"]
