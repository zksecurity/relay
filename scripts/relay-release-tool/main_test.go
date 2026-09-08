package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
)

func TestPinnedModuleInventory(t *testing.T) {
	fresh := func() []*debug.Module {
		result := []*debug.Module{}
		for _, pin := range pinnedModules {
			p := pin
			result = append(result, &p)
		}
		return result
	}
	if err := validatePinnedModules(fresh()); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func([]*debug.Module) []*debug.Module{
		"missing":     func(d []*debug.Module) []*debug.Module { return d[1:] },
		"extra":       func(d []*debug.Module) []*debug.Module { return append(d, &debug.Module{Path: "unexpected"}) },
		"duplicate":   func(d []*debug.Module) []*debug.Module { d[1] = d[0]; return d },
		"version":     func(d []*debug.Module) []*debug.Module { d[0].Version = "v9.9.9"; return d },
		"checksum":    func(d []*debug.Module) []*debug.Module { d[0].Sum = "h1:changed"; return d },
		"replacement": func(d []*debug.Module) []*debug.Module { d[0].Replace = &debug.Module{Path: "./local"}; return d },
	} {
		t.Run(name, func(t *testing.T) {
			if validatePinnedModules(change(fresh())) == nil {
				t.Fatal("accepted unreviewed module inventory")
			}
		})
	}
}

func TestSignAndVerifyManifest(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	manifest := filepath.Join(dir, "build-package-manifest.json")
	key := filepath.Join(dir, "build-key.hex")
	signature := filepath.Join(dir, "build-package-manifest.sig")
	publicKey := filepath.Join(dir, "build-package-manifest-public-key.hex")
	writeTestFile(t, manifest, []byte("{\"schema\":\"relay-build-package/v1\"}\n"), 0o600)
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index + 1)
	}
	writeTestFile(t, key, []byte(hex.EncodeToString(seed)+"\n"), 0o600)

	err := runSign([]string{
		"--input", manifest,
		"--private-key", key,
		"--signature-out", signature,
		"--public-key-out", publicKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyManifestSignature(dir, publicKey, data); err != nil {
		t.Fatal(err)
	}
	data[0] ^= 1
	if err := verifyManifestSignature(dir, publicKey, data); err == nil {
		t.Fatal("tampered manifest signature unexpectedly verified")
	}
}

func TestKeygenCreatesMatchingFreshKeypair(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	privatePath := filepath.Join(dir, "private.hex")
	publicPath := filepath.Join(dir, "public.hex")
	if err := runKeygen([]string{
		"--private-key-out", privatePath,
		"--public-key-out", publicPath,
	}); err != nil {
		t.Fatal(err)
	}
	privateHex, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(privateHex)))
	if err != nil {
		t.Fatal(err)
	}
	publicHex, err := os.ReadFile(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	wantPublic := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	if strings.TrimSpace(string(publicHex)) != hex.EncodeToString(wantPublic) {
		t.Fatal("generated public key does not match private seed")
	}
	if err := runKeygen([]string{
		"--private-key-out", privatePath,
		"--public-key-out", filepath.Join(dir, "second-public.hex"),
	}); err == nil {
		t.Fatal("keygen overwrote an existing private key")
	}
}

func TestSignRejectsPermissivePrivateKey(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose Unix permission bits")
	}
	t.Parallel()
	dir := t.TempDir()
	manifest := filepath.Join(dir, "manifest")
	key := filepath.Join(dir, "key")
	writeTestFile(t, manifest, []byte("manifest"), 0o600)
	writeTestFile(t, key, []byte(strings.Repeat("01", ed25519.SeedSize)), 0o644)
	if err := os.Chmod(key, 0o644); err != nil {
		t.Fatal(err)
	}
	err := runSign([]string{
		"--input", manifest,
		"--private-key", key,
		"--signature-out", filepath.Join(dir, "signature"),
		"--public-key-out", filepath.Join(dir, "public"),
	})
	if err == nil || !strings.Contains(err.Error(), "group/world") {
		t.Fatalf("got error %v, want group/world permission rejection", err)
	}
}

func TestValidateCommit(t *testing.T) {
	t.Parallel()
	valid := strings.Repeat("ab", 20)
	if err := validateCommit(valid); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{
		strings.Repeat("0", 40),
		strings.ToUpper(valid),
		valid[:39],
		strings.Repeat("zz", 20),
	} {
		if err := validateCommit(invalid); err == nil {
			t.Fatalf("invalid commit %q was accepted", invalid)
		}
	}
}

func TestHashRegularRejectsSymlink(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	writeTestFile(t, target, []byte("content"), 0o600)
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := hashRegular(link); err == nil {
		t.Fatal("hashRegular accepted a symbolic link")
	}
}

func writeTestFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
}
