package circuit

import (
	"path/filepath"
	"testing"

	"github.com/pigfox/zk-kyc-pass/internal/consts"
)

func TestKYCPassConfig(t *testing.T) {
	cfg := KYCPassConfig("/repo")
	if cfg.Name != "kycpass" {
		t.Fatalf("Name = %q", cfg.Name)
	}
	if cfg.Depth != consts.TreeDepth {
		t.Fatalf("Depth = %d, want %d", cfg.Depth, consts.TreeDepth)
	}
	if cfg.BuildDir != filepath.Join("/repo", "circuits", "build") {
		t.Fatalf("BuildDir = %q", cfg.BuildDir)
	}
	if cfg.Wasm != filepath.Join("/repo", "circuits", "build", "kycpass_js", "kycpass.wasm") {
		t.Fatalf("Wasm = %q", cfg.Wasm)
	}
	if cfg.Zkey != filepath.Join("/repo", "circuits", "build", "kycpass_final.zkey") {
		t.Fatalf("Zkey = %q", cfg.Zkey)
	}
	if cfg.Vkey != filepath.Join("/repo", "circuits", "build", "verification_key.json") {
		t.Fatalf("Vkey = %q", cfg.Vkey)
	}
}

func TestDeliveryConfig(t *testing.T) {
	cfg := DeliveryConfig("/repo")
	if cfg.Name != "delivery" {
		t.Fatalf("Name = %q", cfg.Name)
	}
	if cfg.Depth != consts.TreeDepth {
		t.Fatalf("Depth = %d", cfg.Depth)
	}
	if cfg.Wasm != filepath.Join("/repo", "circuits", "build", "delivery_js", "delivery.wasm") {
		t.Fatalf("Wasm = %q", cfg.Wasm)
	}
	if cfg.Zkey != filepath.Join("/repo", "circuits", "build", "delivery_final.zkey") {
		t.Fatalf("Zkey = %q", cfg.Zkey)
	}
}
