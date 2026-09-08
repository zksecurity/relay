// Rehearsal-only bridge, built inside the pinned proof-tool source tree by the
// opt-in integration test. Never shipped in a Relay role image or release.
package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"golang.org/x/crypto/blake2b"
	"proof-tool/internal/circuit/rehearsal"
	"proof-tool/internal/mpcceremony"
	"proof-tool/internal/prover"
)

func main() {
	if len(os.Args) != 5 {
		panic("usage: tiny-public-evidence PRELIMINARY COORDINATOR_PUBLIC CEREMONY_ID OUTPUT")
	}
	if err := run(os.Args[1], os.Args[2], os.Args[3], os.Args[4]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(preliminary, key, ceremonyID, output string) error {
	public, err := os.ReadFile(key)
	if err != nil {
		return err
	}
	manifest, err := mpcceremony.VerifyPreliminaryFinalKeys(preliminary, string(public))
	if err != nil {
		return err
	}
	if manifest.CeremonyID != ceremonyID || manifest.Circuit.KeyVersion != mpcceremony.KeyVersionRehearsal {
		return fmt.Errorf("requires exact tiny rehearsal preliminary keys")
	}
	circuit, err := mpcceremony.CompileForKeyVersion(mpcceremony.KeyVersionRehearsal)
	if err != nil {
		return err
	}
	credential, err := hex.DecodeString(mpcceremony.GoldenPublicCredentialHex)
	if err != nil {
		return err
	}
	destination, err := hex.DecodeString(mpcceremony.GoldenPublicDestinationHex)
	if err != nil {
		return err
	}
	preimage := append([]byte(mpcceremony.DestinationPublicDomain), credential...)
	digest := blake2b.Sum256(append(preimage, destination...))
	reversed := bytes.Clone(digest[:])
	for l, r := 0, len(reversed)-1; l < r; l, r = l+1, r-1 {
		reversed[l], reversed[r] = reversed[r], reversed[l]
	}
	scalar := new(big.Int).SetBytes(reversed)
	scalar.Mod(scalar, ecc.BLS12_381.ScalarField())
	// This registered tiny circuit proves X^3 = Pub. The repository's golden
	// public digest is a cube in the scalar field; derive a root without changing
	// that public fixture or weakening the real circuit's constraint.
	order := new(big.Int).Sub(ecc.BLS12_381.ScalarField(), big.NewInt(1))
	order.Div(order, big.NewInt(3))
	exponent := new(big.Int).ModInverse(big.NewInt(3), order)
	if exponent == nil {
		return fmt.Errorf("unsupported rehearsal scalar field")
	}
	secret := new(big.Int).Exp(scalar, exponent, ecc.BLS12_381.ScalarField())
	if new(big.Int).Exp(secret, big.NewInt(3), ecc.BLS12_381.ScalarField()).Cmp(scalar) != 0 {
		return fmt.Errorf("golden public fixture is not a cube")
	}
	witness, err := frontend.NewWitness(&rehearsal.Circuit{Pub: scalar, X: secret}, ecc.BLS12_381.ScalarField())
	if err != nil {
		return err
	}
	pk, err := prover.LoadPK(filepath.Join(preliminary, mpcceremony.NativeProvingKeyFile))
	if err != nil {
		return err
	}
	proof, err := groth16.Prove(circuit.R1CS, pk, witness)
	if err != nil {
		return err
	}
	cardanoProof, format, err := prover.SerializeCardanoProof(proof)
	if err != nil {
		return err
	}
	vk, err := os.ReadFile(filepath.Join(preliminary, mpcceremony.CardanoVKBytesFile))
	if err != nil {
		return err
	}
	evidence := mpcceremony.PublicFinalizationEvidence{Schema: mpcceremony.PublicEvidenceSchema, CeremonyID: ceremonyID, Fixture: mpcceremony.PublicEvidenceFixture, CredentialHex: hex.EncodeToString(credential), DestinationHex: hex.EncodeToString(destination), PublicInputDigestHex: hex.EncodeToString(digest[:]), CardanoProofHex: hex.EncodeToString(cardanoProof), CardanoProofFormat: format, CardanoProofRawDigest: mpcceremony.NewDigest(cardanoProof), CardanoVerifyingKey: mpcceremony.ArtifactRef{Name: mpcceremony.CardanoVKBytesFile, Digest: mpcceremony.NewDigest(vk)}}
	data, err := mpcceremony.MarshalCanonical(evidence)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
