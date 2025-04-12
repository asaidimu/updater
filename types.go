package updater

import (
	"crypto/rsa"
	"net/http"
)

// UpdateInfo represents metadata for an available update.
type UpdateInfo struct {
	Version   string // New version (e.g., "1.0.1")
	URL       string // Download URL (e.g., "/api/download/slug-xyz123")
	TTL       int    // Time-to-live in seconds
	Changelog string // Release notes
	Checksum  string // SHA256 checksum (format: "SHA256:hex")
}

// PermitUpdateFunc decides whether to proceed with an update.
type PermitUpdateFunc func(info UpdateInfo) bool

// Config holds updater configuration.
type Config struct {
	ServerURL        string           // Update server URL (e.g., "https://update.example.com")
	AppName          string           // Application name (e.g., "myapp")
	Version          string           // Current version (e.g., "1.0.0")
	PrivateKey       *rsa.PrivateKey  // RSA key for signing update requests
	Platform         string           // Platform (e.g., "windows")
	Architecture     string           // Architecture (e.g., "amd64")
	ClientID         string           // Unique client identifier
	SpawnArgsFunc    func(oldPath, newPath string) []string // Returns args for spawning updater
	PermitUpdateFunc PermitUpdateFunc // Decides if update is allowed
}

// Updater manages the update process.
type Updater struct {
	config     Config
	httpClient *http.Client
}
