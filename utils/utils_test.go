package utils

import (
	"os"
	"path/filepath"
	"tblocker/config"
	"testing"
)

func TestIsBypassedIP(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "config_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	configContent := `
LogFile: "/var/log/test.log"
BlockDuration: 10
TorrentTag: "TORRENT"
BypassIPS:
  - "127.0.0.1"
  - "192.168.1.100"
`

	configFile := filepath.Join(tempDir, "config.yaml")
	err = os.WriteFile(configFile, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	err = config.LoadConfig(configFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if !IsBypassedIP("127.0.0.1") {
		t.Error("Expected 127.0.0.1 to be bypassed")
	}

	if !IsBypassedIP("192.168.1.100") {
		t.Error("Expected 192.168.1.100 to be bypassed")
	}

	if IsBypassedIP("192.168.1.200") {
		t.Error("Expected 192.168.1.200 to not be bypassed")
	}
}

func TestSendWebhook(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "config_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	configContent := `
LogFile: "/var/log/test.log"
BlockDuration: 10
TorrentTag: "TORRENT"
SendWebhook: true
WebhookURL: "https://httpbin.org/post"
WebhookTemplate: '{"username":"%s","ip":"%s","action":"%s"}'
`

	configFile := filepath.Join(tempDir, "config.yaml")
	err = os.WriteFile(configFile, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	err = config.LoadConfig(configFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	SendWebhook("testuser", "192.168.1.100", "block")
}

func TestSendWebhookDisabled(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "config_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	configContent := `
LogFile: "/var/log/test.log"
BlockDuration: 10
TorrentTag: "TORRENT"
SendWebhook: false
`

	configFile := filepath.Join(tempDir, "config.yaml")
	err = os.WriteFile(configFile, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	err = config.LoadConfig(configFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	SendWebhook("testuser", "192.168.1.100", "block")
}

func TestParseSourceLogEntry(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "config_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	configContent := `
LogFile: "/var/log/test.log"
BlockDuration: 10
TorrentTag: "TORRENT"
JsonEntryTag: ""
`

	configFile := filepath.Join(tempDir, "config.yaml")
	err = os.WriteFile(configFile, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	err = config.LoadConfig(configFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if config.JsonEntryTag != "" {
		t.Fatalf("JsonEntryTag is not empty")
	}

	line := `from 1.2.3.4:54279 accepted tcp:5.6.7.8:24033 [vless-tcp-reality -> TORRENT] email: 9-macbook`

	ip, username, valid := parseLogEntryFast(line)
	if !valid {
		t.Fatal("log entry parse. valid == false")
	}
	if ip != "1.2.3.4:" {
		t.Fatalf("ip parse. actual: %s required %s", ip, "1.2.3.4:54279")
	}
	if username != "9-macbook" {
		t.Fatal("username parse. actual: %s required %s", username, "9-macbook")
	}
}

func TestParseJsonLogEntry(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "config_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	configContent := `
LogFile: "/var/log/test.log"
BlockDuration: 10
TorrentTag: "TORRENT"
JsonEntryTag: "msg"
`

	configFile := filepath.Join(tempDir, "config.yaml")
	err = os.WriteFile(configFile, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	err = config.LoadConfig(configFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if config.JsonEntryTag == "" {
		t.Fatalf("JsonEntryTag is empty")
	}

	line := `{"level":"info","ts":"2026-09-12 10:58:47 UTC","msg":"[xray] from 1.2.3.4:54279 accepted tcp:5.6.7.8:24033 [vless-tcp-reality -> TORRENT] email: 9-macbook"}`

	entry, valid := extractJsonLogEntry(line)
	if !valid {
		t.Fatal("Invalid log entry format: Json entry tag missing")
	}
	ip, username, valid := parseLogEntryFast(entry)
	if !valid {
		t.Fatal("log entry parse. valid == false")
	}
	if ip != "1.2.3.4:" {
		t.Fatalf("ip parse. actual: %s required %s", ip, "1.2.3.4:54279")
	}
	if username != "9-macbook" {
		t.Fatal("username parse. actual: %s required %s", username, "9-macbook")
	}
}
