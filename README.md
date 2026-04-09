# PVault

A hardened secrets vault with cryptographic access control, hierarchical key wrapping, and an immutable audit trail. Built as a gRPC service backed by PostgreSQL.

## Overview

PVault stores secrets in a way that preserves confidentiality even if the database is fully compromised. Encryption is enforced at every layer: secrets are encrypted with per-secret keys, which are wrapped by per-vault keys, which are wrapped by the service master key. Users can only decrypt secrets they are members of, and only when they supply their own User Root Key.

## Features

- **Hierarchical key wrapping** — three-tier key model: Service Master Key → Vault Key → Data Encryption Key
- **Per-user access control** — each user's Vault Key copy is wrapped with their own User Root Key (Ku)
- **Role-based capabilities** — membership carries a role and a capability set (e.g. `see`, `connect`, `change`)
- **Immutable audit trail** — HMAC-chained audit log; each entry covers the previous entry's HMAC
- **gRPC API** — strongly typed, transport-agnostic, TLS-capable
- **Pluggable backends** — PostgreSQL for production, in-memory mock for testing

## Quick Start

### Prerequisites

- Go 1.21+
- PostgreSQL 14+
- `protoc` and `protoc-gen-go` / `protoc-gen-go-grpc` (only if regenerating protos)

### Run

```bash
go run ./cmd/main.go \
  --listen :50051 \
  --db "postgres://postgres:postgres@localhost:5432/pvault?sslmode=disable"
```

Run without `--db` to use the in-memory store (useful for development):

```bash
go run ./cmd/main.go --listen :50051
```

### Build

```bash
go build -o pvault-server ./cmd/main.go
```

### Test

```bash
make unit-tests
```

Integration tests spin up a real PostgreSQL container via testcontainers and require Docker.

### Regenerate Protos

```bash
make generate
```

## CLI Flags

| Flag | Short | Default | Description |
|---|---|---|---|
| `--listen` | `-l` | `:50051` | gRPC listen address |
| `--db` | `-d` | _(empty)_ | PostgreSQL connection string; omit for in-memory mode |
| `--tls` | `-t` | `false` | Enable TLS |
| `--tls-cert` | | `cert/server.crt` | TLS certificate file |
| `--tls-key` | | `cert/server.key` | TLS private key file |
| `--log-level` | `-v` | `info` | Log verbosity: `debug`, `info`, `warn`, `error` |

## gRPC API

All requests require a `Bearer <token>` value in the `authorization` metadata header.

### Membership

**CreateMembership** — Onboard a user to a vault. The vault's key hierarchy is initialized on the first call.

```protobuf
rpc CreateMembership(CreateMembershipRequest) returns (MembershipResponse)

message CreateMembershipRequest {
  string user_id        = 1; // UUID
  string vault_id       = 2; // UUID
  bytes  user_root_key  = 3; // Ku — used to wrap the vault key for this user
  string role           = 4; // e.g. "admin", "operator"
  repeated string capabilities = 5; // e.g. ["see", "connect"]
}
```

**ListAuthorizedVaults** — Return vault IDs the calling user has membership in.

```protobuf
rpc ListAuthorizedVaults(ListVaultsRequest) returns (ListVaultsResponse)
```

### Secrets

**ProtectSecret** — Encrypt and store a plaintext secret.

```protobuf
rpc ProtectSecret(ProtectSecretRequest) returns (SecretResponse)

message ProtectSecretRequest {
  string secret_id  = 1; // UUID — caller-assigned
  string vault_id   = 2; // UUID
  string plaintext  = 3;
}
```

**UncoverSecret** — Decrypt and return a secret, subject to capability check.

```protobuf
rpc UncoverSecret(UncoverSecretRequest) returns (UncoverSecretResponse)

message UncoverSecretRequest {
  string secret_id = 1; // UUID
  string vault_id  = 2; // UUID
  string action    = 3; // Capability required, e.g. "see"
}
```

### Audit

**RecordAuditLog** — Append an entry to the HMAC-chained audit log.

```protobuf
rpc RecordAuditLog(AuditLogRequest) returns (AuditLogResponse)

message AuditLogRequest {
  string source_service  = 1;
  string correlation_id  = 2; // UUID
  string event_type      = 3;
  string actor_id        = 4; // UUID
  string action_status   = 5; // e.g. "success", "failure"
  string payload_json    = 6; // Arbitrary JSON metadata
}

message AuditLogResponse {
  int64 audit_id  = 1;
  bytes curr_hmac = 2; // HMAC of this entry, for verification
}
```

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for a full description of the layered design, cryptographic model, and key flows.

## Project Layout

```
api/v1/              Protocol buffer definitions
cmd/                 CLI entry point and server factory
internal/
  core/
    domain/          Entity models and domain errors
    ports/           Interface contracts (repository, crypto, service)
    service/         Business logic implementations
  adapters/
    crypto/          AES-256-GCM crypto adapter
    pg/              PostgreSQL persistence adapter
    mock/            In-memory adapters for testing
    token/           JWT (JWKS) and API key token validators
  platform/
    grpc/            gRPC server, auth interceptor, request handlers
pkg/api/v1/          Generated protobuf Go code
```