# dynolabs-io/api

Go microservices backend for the Dynolabs vCard mobile app.

| Service | Path | Purpose |
|---|---|---|
| `vcard-api` | `services/vcard-api/` | Cards CRUD + slug resolution |
| `pass-signer` | `services/pass-signer/` | Apple `.pkpass` + Google Wallet JWT signing |
| `photo-cdn` | `services/photo-cdn/` | S3-backed avatar storage and serving |
| `linkedin-oauth` | `services/linkedin-oauth/` | LinkedIn OAuth callback + profile fetch |
| `web-profile` | `services/web-profile/` | SSR public profile page (`dynolabs.io/c/<slug>`) |

## Architecture
- Go 1.22, single workspace (`go.work`) covering all services
- Each service builds to a distroless static binary
- HTTP `:8080` per service, `/healthz` and `/readyz` on every service
- CAP-AP design: PostgreSQL source-of-truth, NATS for replication, eventual consistency
- Stub-mode flags let services deploy before external credentials (Apple Pass cert, LinkedIn OAuth, Google Wallet) are provisioned

## CI/CD
GitHub Actions (`.github/workflows/build.yml`):
1. Matrix-builds all 5 services on push to `main`
2. Pushes SHA-tagged images to `ghcr.io/dynolabs-io/api/<service>:<sha>`
3. Triggers SHA bump in `openova-io/openova-private` for Flux to pick up

## Deployment
Flux-managed under `openova-io/openova-private/clusters/contabo-mkt/apps/dynolabs/`.

## Local development
```bash
cd services/vcard-api
go run .
curl localhost:8080/healthz
```

## Tracking
Umbrella issue: `dynolabs-io/vcard#1`.
