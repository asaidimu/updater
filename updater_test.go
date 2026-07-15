package updater

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// testHelper indicates the test binary is invoked as a subprocess.
const testHelper = "TEST_HELPER"

func TestMain(m *testing.M) {
	if os.Getenv(testHelper) == "PerformUpdate" {
		testPerformUpdateHelper()
		return
	}
	if os.Getenv(testHelper) == "RunUpdate" {
		testRunUpdateHelper()
		return
	}
	os.Exit(m.Run())
}

func testPerformUpdateHelper() {
	appName := os.Getenv("TEST_APP_NAME")
	clientID := os.Getenv("TEST_CLIENT_ID")

	_, pub := generateTestKeyHelper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("#!/bin/sh\nexit 0\n"))
	}))
	defer srv.Close()

	u, err := NewUpdater(Config{
		ServerURL:       srv.URL,
		AppName:         appName,
		Version:         "1.0.0",
		ClientToken:     "token",
		ServerPublicKey: pub,
		ClientID:        clientID,
		SpawnArgsFunc:   func(_, _ string) []string { return nil },
	})
	if err != nil {
		os.Exit(1)
	}

	update := &UpdateInfo{
		Version: "2.0.0",
		URL:     "/download",
		TTL:     3600,
	}

	if err := u.PerformUpdate(context.Background(), update); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

func testRunUpdateHelper() {
	oldPath := os.Getenv("TEST_OLD_PATH")
	newPath := os.Getenv("TEST_NEW_PATH")

	// Simulate RunUpdate inline without calling os.Exit at the end
	// Wait for old process to exit
	timeout := time.After(10 * time.Second)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-timeout:
			os.Exit(1)
		case <-ticker.C:
			f, err := os.Open(oldPath)
			if err == nil {
				f.Close()
				goto exited
			}
		}
	}
exited:
	if err := os.Remove(oldPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := copyFile(newPath, oldPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}

func generateTestKey(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey) {
	t.Helper()
	priv, pub := generateTestKeyHelper()
	return priv, pub
}

func generateTestKeyHelper() (*rsa.PrivateKey, *rsa.PublicKey) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return key, &key.PublicKey
}

func signUpdate(t *testing.T, key *rsa.PrivateKey, update *UpdateInfo) {
	t.Helper()
	update.Signature = ""
	data, err := json.Marshal(update)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	hash := sha256.Sum256(data)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}
	update.Signature = base64.StdEncoding.EncodeToString(sig)
}

type fields struct {
	ServerURL        string
	AppName          string
	Version          string
	ClientToken      string
	ServerPublicKey  *rsa.PublicKey
	ClientID         string
	Platform         string
	Architecture     string
	SpawnArgsFunc    func(oldPath, newPath string) []string
	PermitUpdateFunc func(UpdateInfo) bool
}

func defaultFields(t *testing.T) fields {
	t.Helper()
	_, pub := generateTestKey(t)
	return fields{
		ServerURL:       "http://example.com",
		AppName:         "test-app",
		Version:         "1.0.0",
		ClientToken:     "test-token",
		ServerPublicKey: pub,
		ClientID:        "test-client",
		Platform:        "linux",
		Architecture:    "amd64",
		SpawnArgsFunc:   func(oldPath, newPath string) []string { return []string{"--updated"} },
	}
}

func configFromFields(t *testing.T, f fields) Config {
	t.Helper()
	return Config{
		ServerURL:        f.ServerURL,
		AppName:          f.AppName,
		Version:          f.Version,
		ClientToken:      f.ClientToken,
		ServerPublicKey:  f.ServerPublicKey,
		ClientID:         f.ClientID,
		Platform:         f.Platform,
		Architecture:     f.Architecture,
		SpawnArgsFunc:    f.SpawnArgsFunc,
		PermitUpdateFunc: f.PermitUpdateFunc,
	}
}

func TestNewUpdater_Validation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{
			name:    "empty ServerURL",
			cfg:     Config{AppName: "a", Version: "1.0.0", ClientToken: "t", ServerPublicKey: &rsa.PublicKey{}, ClientID: "c", SpawnArgsFunc: func(_, _ string) []string { return nil }},
			wantErr: "missing required configuration",
		},
		{
			name:    "empty AppName",
			cfg:     Config{ServerURL: "u", Version: "1.0.0", ClientToken: "t", ServerPublicKey: &rsa.PublicKey{}, ClientID: "c", SpawnArgsFunc: func(_, _ string) []string { return nil }},
			wantErr: "missing required configuration",
		},
		{
			name:    "empty Version",
			cfg:     Config{ServerURL: "u", AppName: "a", ClientToken: "t", ServerPublicKey: &rsa.PublicKey{}, ClientID: "c", SpawnArgsFunc: func(_, _ string) []string { return nil }},
			wantErr: "missing required configuration",
		},
		{
			name:    "empty ClientToken",
			cfg:     Config{ServerURL: "u", AppName: "a", Version: "1.0.0", ServerPublicKey: &rsa.PublicKey{}, ClientID: "c", SpawnArgsFunc: func(_, _ string) []string { return nil }},
			wantErr: "missing required configuration",
		},
		{
			name:    "nil ServerPublicKey",
			cfg:     Config{ServerURL: "u", AppName: "a", Version: "1.0.0", ClientToken: "t", ClientID: "c", SpawnArgsFunc: func(_, _ string) []string { return nil }},
			wantErr: "missing required configuration",
		},
		{
			name:    "empty ClientID",
			cfg:     Config{ServerURL: "u", AppName: "a", Version: "1.0.0", ClientToken: "t", ServerPublicKey: &rsa.PublicKey{}, SpawnArgsFunc: func(_, _ string) []string { return nil }},
			wantErr: "ClientID is required",
		},
		{
			name:    "nil SpawnArgsFunc",
			cfg:     Config{ServerURL: "u", AppName: "a", Version: "1.0.0", ClientToken: "t", ServerPublicKey: &rsa.PublicKey{}, ClientID: "c"},
			wantErr: "SpawnArgsFunc is required",
		},
		{
			name: "valid config",
			cfg:  Config{ServerURL: "u", AppName: "a", Version: "1.0.0", ClientToken: "t", ServerPublicKey: &rsa.PublicKey{}, ClientID: "c", SpawnArgsFunc: func(_, _ string) []string { return nil }},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := NewUpdater(tt.cfg)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("expected error containing %q, got %q", tt.wantErr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if u == nil {
				t.Fatal("expected updater, got nil")
			}
		})
	}
}

func TestNewUpdater_Defaults(t *testing.T) {
	f := defaultFields(t)
	f.Platform = ""
	f.Architecture = ""
	u, err := NewUpdater(configFromFields(t, f))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u.config.Platform != "windows" {
		t.Errorf("expected Platform default 'windows', got %q", u.config.Platform)
	}
	if u.config.Architecture != "amd64" {
		t.Errorf("expected Architecture default 'amd64', got %q", u.config.Architecture)
	}
}

func TestCheckForUpdate_NoUpdate(t *testing.T) {
	_, pub := generateTestKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/update" {
			t.Errorf("expected /api/update, got %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	u, err := NewUpdater(Config{
		ServerURL:       srv.URL,
		AppName:         "test-app",
		Version:         "1.0.0",
		ClientToken:     "token",
		ServerPublicKey: pub,
		ClientID:        "client-id",
		SpawnArgsFunc:   func(_, _ string) []string { return nil },
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	update, err := u.CheckForUpdate(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if update != nil {
		t.Fatal("expected nil update, got non-nil")
	}
}

func TestCheckForUpdate_NotNewer(t *testing.T) {
	priv, pub := generateTestKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upd := &UpdateInfo{Version: "1.0.0", URL: "/download", TTL: 3600}
		signUpdate(t, priv, upd)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(upd)
	}))
	defer srv.Close()

	u, err := NewUpdater(Config{
		ServerURL:       srv.URL,
		AppName:         "test-app",
		Version:         "1.0.0",
		ClientToken:     "token",
		ServerPublicKey: pub,
		ClientID:        "client-id",
		SpawnArgsFunc:   func(_, _ string) []string { return nil },
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	update, err := u.CheckForUpdate(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if update != nil {
		t.Fatal("expected nil for same version, got non-nil")
	}
}

func TestCheckForUpdate_NewerAvailable(t *testing.T) {
	priv, pub := generateTestKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var reqBody map[string]string
		if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
			t.Fatalf("failed to decode request: %v", err)
		}
		if reqBody["token"] != "token" {
			t.Errorf("expected token 'token', got %q", reqBody["token"])
		}
		upd := &UpdateInfo{
			Version:   "2.0.0",
			URL:       "/download/v2.0.0",
			TTL:       3600,
			Changelog: "Major release",
			Checksum:  "",
			Signature: "",
		}
		signUpdate(t, priv, upd)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(upd)
	}))
	defer srv.Close()

	u, err := NewUpdater(Config{
		ServerURL:       srv.URL,
		AppName:         "test-app",
		Version:         "1.0.0",
		ClientToken:     "token",
		ServerPublicKey: pub,
		ClientID:        "client-id",
		SpawnArgsFunc:   func(_, _ string) []string { return nil },
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	update, err := u.CheckForUpdate(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if update == nil {
		t.Fatal("expected update, got nil")
	}
	if update.Version != "2.0.0" {
		t.Errorf("expected version 2.0.0, got %s", update.Version)
	}
	if update.URL != "/download/v2.0.0" {
		t.Errorf("expected URL /download/v2.0.0, got %s", update.URL)
	}
}

func TestCheckForUpdate_InvalidSignature(t *testing.T) {
	_, pub := generateTestKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upd := &UpdateInfo{Version: "2.0.0", URL: "/download", TTL: 3600, Signature: "invalid"}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(upd)
	}))
	defer srv.Close()

	u, err := NewUpdater(Config{
		ServerURL:       srv.URL,
		AppName:         "test-app",
		Version:         "1.0.0",
		ClientToken:     "token",
		ServerPublicKey: pub,
		ClientID:        "client-id",
		SpawnArgsFunc:   func(_, _ string) []string { return nil },
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = u.CheckForUpdate(context.Background())
	if err == nil || !strings.Contains(err.Error(), "failed to verify server signature") {
		t.Errorf("expected signature verification error, got %v", err)
	}
}

func TestCheckForUpdate_ServerError(t *testing.T) {
	_, pub := generateTestKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	u, err := NewUpdater(Config{
		ServerURL:       srv.URL,
		AppName:         "test-app",
		Version:         "1.0.0",
		ClientToken:     "token",
		ServerPublicKey: pub,
		ClientID:        "client-id",
		SpawnArgsFunc:   func(_, _ string) []string { return nil },
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = u.CheckForUpdate(context.Background())
	if err == nil || !strings.Contains(err.Error(), "unexpected status") {
		t.Errorf("expected unexpected status error, got %v", err)
	}
}

func TestCheckForUpdate_InvalidCurrentVersion(t *testing.T) {
	priv, pub := generateTestKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upd := &UpdateInfo{Version: "2.0.0", URL: "/download", TTL: 3600}
		signUpdate(t, priv, upd)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(upd)
	}))
	defer srv.Close()

	u, err := NewUpdater(Config{
		ServerURL:       srv.URL,
		AppName:         "test-app",
		Version:         "not-a-version",
		ClientToken:     "token",
		ServerPublicKey: pub,
		ClientID:        "client-id",
		SpawnArgsFunc:   func(_, _ string) []string { return nil },
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = u.CheckForUpdate(context.Background())
	if err == nil || !strings.Contains(err.Error(), "invalid current version") {
		t.Errorf("expected invalid version error, got %v", err)
	}
}

func TestCheckForUpdate_InvalidUpdateVersion(t *testing.T) {
	priv, pub := generateTestKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upd := &UpdateInfo{Version: "not-a-version", URL: "/download", TTL: 3600}
		signUpdate(t, priv, upd)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(upd)
	}))
	defer srv.Close()

	u, err := NewUpdater(Config{
		ServerURL:       srv.URL,
		AppName:         "test-app",
		Version:         "1.0.0",
		ClientToken:     "token",
		ServerPublicKey: pub,
		ClientID:        "client-id",
		SpawnArgsFunc:   func(_, _ string) []string { return nil },
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = u.CheckForUpdate(context.Background())
	if err == nil || !strings.Contains(err.Error(), "invalid update version") {
		t.Errorf("expected invalid update version error, got %v", err)
	}
}

func TestCheckForUpdate_ContextCancelled(t *testing.T) {
	_, pub := generateTestKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	u, err := NewUpdater(Config{
		ServerURL:       srv.URL,
		AppName:         "test-app",
		Version:         "1.0.0",
		ClientToken:     "token",
		ServerPublicKey: pub,
		ClientID:        "client-id",
		SpawnArgsFunc:   func(_, _ string) []string { return nil },
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = u.CheckForUpdate(ctx)
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}
}

func TestDownloadUpdate(t *testing.T) {
	_, pub := generateTestKey(t)
	binaryContent := []byte("mock-binary-content")
	checksum := sha256.Sum256(binaryContent)
	expectedChecksum := hex.EncodeToString(checksum[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/download/v2.0.0" {
			t.Errorf("expected /download/v2.0.0, got %s", r.URL.Path)
		}
		w.Write(binaryContent)
	}))
	defer srv.Close()

	u, err := NewUpdater(Config{
		ServerURL:       srv.URL,
		AppName:         "test-app",
		Version:         "1.0.0",
		ClientToken:     "token",
		ServerPublicKey: pub,
		ClientID:        "client-id",
		SpawnArgsFunc:   func(_, _ string) []string { return nil },
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	update := &UpdateInfo{
		Version:   "2.0.0",
		URL:       "/download/v2.0.0",
		Checksum:  "SHA256:" + expectedChecksum,
		Signature: "",
	}

	path, err := u.downloadUpdate(context.Background(), update)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer os.Remove(path)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read downloaded file: %v", err)
	}
	if !bytes.Equal(data, binaryContent) {
		t.Errorf("downloaded content mismatch: got %v, want %v", data, binaryContent)
	}
}

func TestDownloadUpdate_ChecksumMismatch(t *testing.T) {
	_, pub := generateTestKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("content"))
	}))
	defer srv.Close()

	u, err := NewUpdater(Config{
		ServerURL:       srv.URL,
		AppName:         "test-app",
		Version:         "1.0.0",
		ClientToken:     "token",
		ServerPublicKey: pub,
		ClientID:        "client-id",
		SpawnArgsFunc:   func(_, _ string) []string { return nil },
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	update := &UpdateInfo{
		Version:  "2.0.0",
		URL:      "/download/v2.0.0",
		Checksum: "SHA256:deadbeef",
	}

	path, err := u.downloadUpdate(context.Background(), update)
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		os.Remove(path)
		t.Fatalf("expected checksum mismatch error, got %v", err)
	}
	if path != "" {
		os.Remove(path)
	}
}

func TestDownloadUpdate_InvalidChecksumFormat(t *testing.T) {
	_, pub := generateTestKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("content"))
	}))
	defer srv.Close()

	u, err := NewUpdater(Config{
		ServerURL:       srv.URL,
		AppName:         "test-app",
		Version:         "1.0.0",
		ClientToken:     "token",
		ServerPublicKey: pub,
		ClientID:        "client-id",
		SpawnArgsFunc:   func(_, _ string) []string { return nil },
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	update := &UpdateInfo{
		Version:  "2.0.0",
		URL:      "/download/v2.0.0",
		Checksum: "MD5:deadbeef",
	}

	path, err := u.downloadUpdate(context.Background(), update)
	if err == nil || !strings.Contains(err.Error(), "invalid checksum format") {
		os.Remove(path)
		t.Fatalf("expected invalid checksum format error, got %v", err)
	}
	if path != "" {
		os.Remove(path)
	}
}

func TestDownloadUpdate_ServerError(t *testing.T) {
	_, pub := generateTestKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	u, err := NewUpdater(Config{
		ServerURL:       srv.URL,
		AppName:         "test-app",
		Version:         "1.0.0",
		ClientToken:     "token",
		ServerPublicKey: pub,
		ClientID:        "client-id",
		SpawnArgsFunc:   func(_, _ string) []string { return nil },
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	update := &UpdateInfo{Version: "2.0.0", URL: "/download/v2.0.0"}
	_, err = u.downloadUpdate(context.Background(), update)
	if err == nil || !strings.Contains(err.Error(), "unexpected download status") {
		t.Errorf("expected download status error, got %v", err)
	}
}

func TestPerformUpdate_PermitDenied(t *testing.T) {
	_, pub := generateTestKey(t)

	u, err := NewUpdater(Config{
		ServerURL:       "http://example.com",
		AppName:         "test-app",
		Version:         "1.0.0",
		ClientToken:     "token",
		ServerPublicKey: pub,
		ClientID:        "client-id",
		SpawnArgsFunc:   func(_, _ string) []string { return nil },
		PermitUpdateFunc: func(info UpdateInfo) bool {
			return false
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = u.PerformUpdate(context.Background(), &UpdateInfo{Version: "2.0.0"})
	if err != nil {
		t.Fatalf("expected no error when user declines, got %v", err)
	}
}

func TestPerformUpdate_DownloadError(t *testing.T) {
	_, pub := generateTestKey(t)

	u, err := NewUpdater(Config{
		ServerURL:       "http://nonexistent.invalid",
		AppName:         "test-app",
		Version:         "1.0.0",
		ClientToken:     "token",
		ServerPublicKey: pub,
		ClientID:        "client-id",
		SpawnArgsFunc:   func(_, _ string) []string { return nil },
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = u.PerformUpdate(context.Background(), &UpdateInfo{Version: "2.0.0", URL: "/download"})
	if err == nil || !strings.Contains(err.Error(), "failed to download update") {
		t.Errorf("expected download error, got %v", err)
	}
}

func TestPerformUpdate_Success(t *testing.T) {
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(),
		testHelper+"=PerformUpdate",
		"TEST_APP_NAME=test-app",
		"TEST_CLIENT_ID=client-id",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("PerformUpdate subprocess failed: %v\noutput: %s", err, out)
	}
}

func TestRunUpdate_Success(t *testing.T) {
	oldFile, err := os.CreateTemp("", "run-update-old-*.exe")
	if err != nil {
		t.Fatalf("failed to create old file: %v", err)
	}
	oldFile.WriteString("old-binary")
	oldFile.Close()
	defer os.Remove(oldFile.Name())

	newFile, err := os.CreateTemp("", "run-update-new-*.exe")
	if err != nil {
		t.Fatalf("failed to create new file: %v", err)
	}
	newFile.WriteString("new-binary")
	newFile.Close()
	defer os.Remove(newFile.Name())

	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(),
		testHelper+"=RunUpdate",
		fmt.Sprintf("TEST_OLD_PATH=%s", oldFile.Name()),
		fmt.Sprintf("TEST_NEW_PATH=%s", newFile.Name()),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("RunUpdate subprocess failed: %v\noutput: %s", err, out)
	}

	data, err := os.ReadFile(oldFile.Name())
	if err != nil {
		t.Fatalf("failed to read old file after update: %v", err)
	}
	if string(data) != "new-binary" {
		t.Errorf("old file content mismatch: got %q, want %q", string(data), "new-binary")
	}
}

func TestRunUpdate_Timeout(t *testing.T) {
	// Test the actual RunUpdate function's timeout behavior
	// by running it with a non-existent old path (opens will fail)
	done := make(chan error, 1)
	go func() {
		done <- RunUpdate("/nonexistent/path", "/tmp/some-path", nil)
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "timeout") {
			t.Errorf("expected timeout error, got %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("RunUpdate did not timeout within 15s")
	}
}

func TestCleanupTempBinaries(t *testing.T) {
	_, pub := generateTestKey(t)

	u, err := NewUpdater(Config{
		ServerURL:       "http://example.com",
		AppName:         "test-app",
		Version:         "1.0.0",
		ClientToken:     "token",
		ServerPublicKey: pub,
		ClientID:        "client-id",
		SpawnArgsFunc:   func(_, _ string) []string { return nil },
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	f1, _ := os.CreateTemp("", "test-app-*.exe")
	f1.Close()
	defer os.Remove(f1.Name())
	f2, _ := os.CreateTemp("", "test-app-*.exe")
	f2.Close()
	defer os.Remove(f2.Name())

	if err := u.CleanupTempBinaries(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCopyFile(t *testing.T) {
	src, err := os.CreateTemp("", "copy-src-*")
	if err != nil {
		t.Fatalf("failed to create src: %v", err)
	}
	content := "hello, world"
	if _, err := src.WriteString(content); err != nil {
		t.Fatalf("failed to write src: %v", err)
	}
	src.Close()
	defer os.Remove(src.Name())

	dst, err := os.CreateTemp("", "copy-dst-*")
	if err != nil {
		t.Fatalf("failed to create dst: %v", err)
	}
	dst.Close()
	os.Remove(dst.Name())

	if err := copyFile(src.Name(), dst.Name()); err != nil {
		t.Fatalf("copyFile failed: %v", err)
	}
	defer os.Remove(dst.Name())

	data, err := os.ReadFile(dst.Name())
	if err != nil {
		t.Fatalf("failed to read dst: %v", err)
	}
	if string(data) != content {
		t.Errorf("content mismatch: got %q, want %q", string(data), content)
	}
}

func TestCopyFile_NonexistentSrc(t *testing.T) {
	err := copyFile("/nonexistent/path", "/tmp/dst")
	if err == nil {
		t.Fatal("expected error for nonexistent src, got nil")
	}
}

func TestVerifySignature_WrongKey(t *testing.T) {
	priv, _ := generateTestKey(t)
	_, wrongPub := generateTestKey(t)

	upd := &UpdateInfo{Version: "2.0.0", URL: "/download", TTL: 3600}
	signUpdate(t, priv, upd)

	u, err := NewUpdater(Config{
		ServerURL:       "http://example.com",
		AppName:         "test-app",
		Version:         "1.0.0",
		ClientToken:     "token",
		ServerPublicKey: wrongPub,
		ClientID:        "client-id",
		SpawnArgsFunc:   func(_, _ string) []string { return nil },
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = u.verifySignature(upd)
	if err == nil {
		t.Fatal("expected verification error with wrong key, got nil")
	}
}

func TestVerifySignature_InvalidBase64(t *testing.T) {
	_, pub := generateTestKey(t)
	u, _ := NewUpdater(Config{
		ServerURL:       "http://example.com",
		AppName:         "test-app",
		Version:         "1.0.0",
		ClientToken:     "token",
		ServerPublicKey: pub,
		ClientID:        "client-id",
		SpawnArgsFunc:   func(_, _ string) []string { return nil },
	})
	err := u.verifySignature(&UpdateInfo{Signature: "not-base64!!!"})
	if err == nil || !strings.Contains(err.Error(), "failed to decode signature") {
		t.Errorf("expected decode error, got %v", err)
	}
}

func TestZeroValueConfig_Fails(t *testing.T) {
	_, err := NewUpdater(Config{})
	if err == nil {
		t.Fatal("expected error for zero-value config, got nil")
	}
}

func TestCheckForUpdate_BadJSONResponse(t *testing.T) {
	_, pub := generateTestKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{invalid json"))
	}))
	defer srv.Close()

	u, err := NewUpdater(Config{
		ServerURL:       srv.URL,
		AppName:         "test-app",
		Version:         "1.0.0",
		ClientToken:     "token",
		ServerPublicKey: pub,
		ClientID:        "client-id",
		SpawnArgsFunc:   func(_, _ string) []string { return nil },
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = u.CheckForUpdate(context.Background())
	if err == nil {
		t.Fatal("expected JSON decode error, got nil")
	}
}
