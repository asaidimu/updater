# updater

A self-update library for Go applications. updater checks a remote server for newer versions, downloads and verifies updates, and atomically swaps the running binary.

## Features

- **Version checking** — queries an update server with semver comparison
- **Cryptographic verification** — RSA-signed responses and SHA-256 checksums
- **Permission gating** — optional callback to let users approve or deny updates
- **Safe swap** — replaces the running binary atomically with spawn-and-swap
- **Cleanup** — removes stale temporary binaries

## Installation

```sh
go get github.com/asaidimu/updater
```

## Usage

### Basic setup

```go
import (
    "crypto/rsa"
    "github.com/asaidimu/updater"
)

pubKey := loadPublicKey() // *rsa.PublicKey

u, err := updater.NewUpdater(updater.Config{
    ServerURL:       "https://updates.example.com",
    AppName:         "myapp",
    Version:         "1.0.0",
    ClientToken:     "your-client-token",
    ServerPublicKey: pubKey,
    ClientID:        "unique-client-id",
    SpawnArgsFunc: func(oldPath, newPath string) []string {
        return []string{"--updated", "--old-path", oldPath}
    },
})
```

### Check for updates

```go
ctx := context.Background()
update, err := u.CheckForUpdate(ctx)
if err != nil {
    // handle error
}
if update == nil {
    // already up to date
}
```

### Perform an update

```go
if err := u.PerformUpdate(ctx, update); err != nil {
    // handle error
}
// Application exits; new binary is spawned via SpawnArgsFunc
```

### Run the swap (called by the new process on startup)

```go
// In the updated binary's startup code:
err := updater.RunUpdate(
    oldPath,     // path the old binary was at
    newPath,     // path where the update binary was downloaded
    os.Args[1:], // original arguments
)
```

### Configuration reference

| Field             | Required | Description |
|-------------------|----------|-------------|
| `ServerURL`       | yes      | Base URL of the update server |
| `AppName`         | yes      | Application identifier |
| `Version`         | yes      | Current semver version |
| `ClientToken`     | yes      | Token for server authentication |
| `ServerPublicKey` | yes      | RSA public key for response verification |
| `ClientID`        | yes      | Unique client identifier |
| `SpawnArgsFunc`   | yes      | Returns args for the new process (receives old/new paths) |
| `Platform`        | no       | Target platform (default: `"windows"`) |
| `Architecture`    | no       | Target architecture (default: `"amd64"`) |
| `PermitUpdateFunc`| no       | Optional callback; returning false cancels the update |

### UpdateInfo

| Field       | Type   | Description |
|-------------|--------|-------------|
| `version`   | string | New semver version |
| `url`       | string | Download path (relative to ServerURL) |
| `ttl`       | int    | Time-to-live for the update info |
| `changelog` | string | Release notes |
| `checksum`  | string | SHA-256 checksum of the binary (format: `SHA256:<hex>`) |
| `signature` | string | Base64-encoded RSA signature of the JSON body |

## Server contract

### Check endpoint

`POST /api/update`

Request body:
```json
{
    "name": "myapp",
    "version": "1.0.0",
    "id": "unique-client-id",
    "token": "your-client-token",
    "platform": "linux",
    "architecture": "amd64"
}
```

Responses:
- `204 No Content` — no update available
- `200 OK` — `UpdateInfo` JSON body with a valid RSA signature

## Testing

```sh
go test ./...
```

## License

[MIT](LICENSE.md)
