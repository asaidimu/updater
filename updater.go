package updater

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
)

// NewUpdater creates a new Updater instance.
func NewUpdater(config Config) (*Updater, error) {
	if config.ServerURL == "" || config.AppName == "" || config.Version == "" || config.PrivateKey == nil {
		return nil, fmt.Errorf("missing required configuration: ServerURL, AppName, Version, and PrivateKey must be set")
	}
	if config.ClientID == "" {
		return nil, fmt.Errorf("ClientID is required")
	}
	if config.Platform == "" {
		config.Platform = "windows"
	}
	if config.Architecture == "" {
		config.Architecture = "amd64"
	}
	if config.SpawnArgsFunc == nil {
		return nil, fmt.Errorf("SpawnArgsFunc is required")
	}
	// PermitUpdateFunc is optional; nil means always permit
	return &Updater{
		config:     config,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// CheckForUpdate queries the update server for a newer version.
func (u *Updater) CheckForUpdate(ctx context.Context) (*UpdateInfo, error) {
	hash := sha256.Sum256([]byte(u.config.ClientID))
	signature, err := rsa.SignPKCS1v15(rand.Reader, u.config.PrivateKey, crypto.SHA256, hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign client ID: %w", err)
	}
	reqBody := map[string]string{
		"name":         u.config.AppName,
		"version":      u.config.Version,
		"id":           u.config.ClientID,
		"signature":    base64.StdEncoding.EncodeToString(signature),
		"platform":     u.config.Platform,
		"architecture": u.config.Architecture,
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", u.config.ServerURL+"/api/update", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := u.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to check for update: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil, nil // No update available
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %s", resp.Status)
	}
	var update UpdateInfo
	if err := json.NewDecoder(resp.Body).Decode(&update); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	// Verify version is newer
	current, err := semver.NewVersion(u.config.Version)
	if err != nil {
		return nil, fmt.Errorf("invalid current version %q: %w", u.config.Version, err)
	}
	latest, err := semver.NewVersion(update.Version)
	if err != nil {
		return nil, fmt.Errorf("invalid update version %q: %w", update.Version, err)
	}
	if !latest.GreaterThan(current) {
		return nil, nil
	}
	return &update, nil
}

// PerformUpdate downloads the new binary and initiates the swap, if permitted.
func (u *Updater) PerformUpdate(ctx context.Context, update *UpdateInfo) error {
	// Check user permission
	if u.config.PermitUpdateFunc != nil {
		if !u.config.PermitUpdateFunc(*update) {
			return nil // User declined; no error
		}
	}
	newBinaryPath, err := u.downloadUpdate(ctx, update)
	if err != nil {
		return fmt.Errorf("failed to download update: %w", err)
	}
	executable, err := os.Executable()
	if err != nil {
		os.Remove(newBinaryPath)
		return fmt.Errorf("failed to get current executable: %w", err)
	}
	executable, err = filepath.Abs(executable)
	if err != nil {
		os.Remove(newBinaryPath)
		return fmt.Errorf("failed to resolve executable path: %w", err)
	}
	args := u.config.SpawnArgsFunc(executable, newBinaryPath)
	cmd := exec.Command(newBinaryPath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	if err := cmd.Start(); err != nil {
		os.Remove(newBinaryPath)
		return fmt.Errorf("failed to start updater process: %w", err)
	}
	// Exit to release file lock
	os.Exit(0)
	return nil
}

// downloadUpdate downloads and verifies the new binary.
func (u *Updater) downloadUpdate(ctx context.Context, update *UpdateInfo) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", u.config.ServerURL+update.URL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create download request: %w", err)
	}
	resp, err := u.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to download binary: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected download status: %s", resp.Status)
	}
	tempDir := os.TempDir()
	newBinaryPath := filepath.Join(tempDir, fmt.Sprintf("%s-%s.exe", u.config.AppName, update.Version))
	f, err := os.OpenFile(newBinaryPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0700)
	if err != nil {
		return "", fmt.Errorf("failed to create new binary file: %w", err)
	}
	hasher := sha256.New()
	writer := io.MultiWriter(f, hasher)
	if _, err := io.Copy(writer, resp.Body); err != nil {
		f.Close()
		os.Remove(newBinaryPath)
		return "", fmt.Errorf("failed to write binary: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(newBinaryPath)
		return "", fmt.Errorf("failed to close binary file: %w", err)
	}
	if update.Checksum != "" {
		if !strings.HasPrefix(update.Checksum, "SHA256:") {
			os.Remove(newBinaryPath)
			return "", fmt.Errorf("invalid checksum format")
		}
		expectedChecksum := strings.TrimPrefix(update.Checksum, "SHA256:")
		actualChecksum := hex.EncodeToString(hasher.Sum(nil))
		if actualChecksum != expectedChecksum {
			os.Remove(newBinaryPath)
			return "", fmt.Errorf("checksum mismatch: expected %s, got %s", expectedChecksum, actualChecksum)
		}
	}
	return newBinaryPath, nil
}

// RunUpdate performs the update swap (called by the application in update mode).
func RunUpdate(oldPath, newPath string, normalArgs []string) error {
	// Wait for old process to exit
	timeout := time.After(10 * time.Second)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-timeout:
			return fmt.Errorf("timeout waiting for old process to exit")
		case <-ticker.C:
			f, err := os.Open(oldPath)
			if err == nil {
				f.Close()
				goto exited
			}
		}
	}
exited:
	// Delete old binary
	if err := os.Remove(oldPath); err != nil {
		return fmt.Errorf("failed to delete old binary: %w", err)
	}
	// Copy new binary to old path
	if err := copyFile(newPath, oldPath); err != nil {
		return fmt.Errorf("failed to copy new binary: %w", err)
	}
	// Launch new binary normally
	cmd := exec.Command(oldPath, normalArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start new binary: %w", err)
	}
	// Exit updater
	os.Exit(0)
	return nil
}

// CleanupTempBinaries removes temporary binaries.
func (u *Updater) CleanupTempBinaries() error {
	tempDir := os.TempDir()
	pattern := fmt.Sprintf("%s-*.exe", u.config.AppName)
	matches, err := filepath.Glob(filepath.Join(tempDir, pattern))
	if err != nil {
		return fmt.Errorf("failed to glob temp binaries: %w", err)
	}
	for _, match := range matches {
		if err := os.Remove(match); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to delete temp binary %s: %v\n", match, err)
		}
	}
	return nil
}

// copyFile copies a file from src to dst.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0700)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}
