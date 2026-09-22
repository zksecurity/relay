// Test-only authoring of fresh synthetic legacy definitions. This helper is
// compiled inside the exact pinned proof source; it is never a verifier.
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	m "proof-tool/internal/mpcceremony"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) != 4 {
		return fmt.Errorf("expected generated definition, rehearsal key, fresh output directory")
	}
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		return err
	}
	var d m.CeremonyDefinition
	if err := json.Unmarshal(raw, &d); err != nil {
		return err
	}
	if d.Mode != "rehearsal" || d.Schema != m.DefinitionSchemaV3 || d.ReleaseVerification != "" {
		return fmt.Errorf("only fresh V3 rehearsal fixtures are supported")
	}
	oldID := d.CeremonyID
	d.Schema, d.AssurancePolicy = m.DefinitionSchemaV2, nil
	d.CeremonyID, err = m.ComputeCeremonyID(d)
	if err != nil {
		return err
	}
	if d.CeremonyID == oldID {
		return fmt.Errorf("legacy schema did not change ceremony identity")
	}
	if err := d.Validate(); err != nil {
		return err
	}
	keyRaw, err := os.ReadFile(os.Args[2])
	if err != nil {
		return err
	}
	seed, err := hex.DecodeString(string(bytes.TrimSpace(keyRaw)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return fmt.Errorf("invalid rehearsal coordinator seed")
	}
	key := ed25519.NewKeyFromSeed(seed)
	if hex.EncodeToString(key.Public().(ed25519.PublicKey)) != d.Coordinator.Ed25519PublicKeyHex {
		return fmt.Errorf("rehearsal key differs from coordinator")
	}
	record, signature, err := m.SignRecord(d, d.Coordinator.KeyID, key)
	if err != nil {
		return err
	}
	if err := os.Mkdir(os.Args[3], 0700); err != nil {
		return err
	}
	for name, data := range map[string][]byte{"ceremony.json": record, "ceremony.sig": signature, "coordinator-public-key.hex": []byte(d.Coordinator.Ed25519PublicKeyHex + "\n")} {
		f, err := os.OpenFile(filepath.Join(os.Args[3], name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		_, writeErr := f.Write(data)
		closeErr := f.Close()
		if writeErr != nil {
			return writeErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}
