# dynolabs-io/api — Repo-specific Notes

> This is a product repo (Dynolabs backend for the vCard mobile app and adjacent surfaces). Generic OpenOva platform working principles live in `~/.claude/CLAUDE.md` (user-global).

## What this is

Go microservices backend serving the Dynolabs vCard mobile app (`io.dynolabs.vcard`), the public web profile pages (`dynolabs.io/c/<slug>`), the photo CDN, the LinkedIn OAuth handshake, and Apple Wallet / Google Wallet pass signing. Each service is an independent Go module aggregated via a single workspace (`go.work`), built as a distroless static binary, deployed via Flux from `openova-private/clusters/contabo-mkt/apps/dynolabs/`.

## What lives in this repo

| Concern | Path |
|---|---|
| Cards CRUD + slug resolution | `services/vcard-api/` |
| Apple `.pkpass` + Google Wallet JWT signing | `services/pass-signer/` |
| S3-backed avatar storage + serving | `services/photo-cdn/` |
| LinkedIn OAuth callback + profile fetch | `services/linkedin-oauth/` |
| SSR public profile page | `services/web-profile/` |
| Shared code | `shared/` |
| Go workspace pin | `go.work` |
| CI matrix build | `.github/workflows/build.yml` |

## Tech stack

- Go 1.25 (`go.work`)
- HTTP `:8080` per service, `/healthz` + `/readyz` on every service
- PostgreSQL source-of-truth + NATS for replication (CAP-AP, eventual consistency)
- Stub-mode flags allow deployment before external creds (Apple Pass cert, LinkedIn OAuth, Google Wallet issuer) are provisioned
- Container registry: `ghcr.io/dynolabs-io/api/<service>:<sha>`
- Deploy: Flux on contabo-mkt under `openova-private/clusters/contabo-mkt/apps/dynolabs/`

## Development workflow

```bash
# Run a service locally
cd services/vcard-api
go run .
curl localhost:8080/healthz

# Build all services
go build ./...

# Workspace tests
go test ./...
```

## CI/CD

Push to `main` → matrix build of all 5 services → push SHA-tagged images to GHCR → trigger SHA bump in `openova-private/clusters/contabo-mkt/apps/dynolabs/` → Flux reconciles.

## Tracking

Umbrella issue: `dynolabs-io/vcard#1`.

## Known issues

- (empty for now — populate as discovered)

## Sub-agent cap for this project

Default (per user-global) unless project owner overrides here.
