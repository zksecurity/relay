package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

const tesseraVectorPayloadB64 = "WyJ0ZXNzZXJhOmFzc2lnbm1lbnQtY29uZmlybWF0aW9uOnYxIiwiaHR0cHM6Ly90ZXNzZXJhLmV4YW1wbGUuaW52YWxpZCIsIjAwMDAwMDAwLTAwMDAtNDAwMC04MDAwLTAwMDAwMDAwMDAwMSIsInNoYTI1NjphYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhIiwic2hhMjU2OmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmIiLCJzaGEyNTY6Y2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjYyIsIjAwMDAwMDAwLTAwMDAtNDAwMC04MDAwLTAwMDAwMDAwMDAwMiIsIjEiLCJwYXJ0aWNpcGFudCIsInBoYXNlMSxwaGFzZTIiLCJwYXJ0aWNpcGFudC1leGFtcGxlIiwiOGE4OGUzZGQ3NDA5ZjE5NWZkNTJkYjJkM2NiYTVkNzJjYTY3MDliZjFkOTQxMjFiZjM3NDg4MDFiNDBmNmY1YyIsImRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGQiLCIiLCIwMDAwMDAwMC0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMDAwMDMiLCJlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlIiwiMjAyNi0wOS0wOFQxMjowMDowMFoiLCIyMDI2LTA5LTA5VDEyOjAwOjAwWiJd"

func TestTesseraConfirmationVector(t *testing.T) {
	request := tesseraSignRequest{Schema: tesseraSignRequestSchema, PayloadB64: tesseraVectorPayloadB64}
	payload, values, err := tesseraPayload(request)
	if err != nil {
		t.Fatal(err)
	}
	if values[10] != "participant-example" {
		t.Fatalf("wrong identity: %q", values[10])
	}
	seed := bytes.Repeat([]byte{1}, ed25519.SeedSize)
	signature := ed25519.Sign(ed25519.NewKeyFromSeed(seed), payload)
	const expected = "783b16e98ad520b46634e00db5657679ae832679ed7f144f58f90b698a04a0e92d29e8eb7387c9f385ff7ff20f95be5fe95968d72e4c9158496abd669c81e104"
	if got := hex.EncodeToString(signature); got != expected {
		t.Fatalf("signature = %s, want %s", got, expected)
	}
}

func TestTesseraRejectsNonCanonicalAndUnsafeOrigins(t *testing.T) {
	request := tesseraSignRequest{Schema: tesseraSignRequestSchema, PayloadB64: tesseraVectorPayloadB64}
	payload, err := base64.StdEncoding.DecodeString(request.PayloadB64)
	if err != nil {
		t.Fatal(err)
	}
	nonCanonicalPayload := bytes.Replace(payload, []byte(",\""), []byte(", \""), 1)
	nonCanonicalRequest := tesseraSignRequest{Schema: tesseraSignRequestSchema, PayloadB64: base64.StdEncoding.EncodeToString(nonCanonicalPayload)}
	if _, _, err := tesseraPayload(nonCanonicalRequest); err == nil {
		t.Fatal("accepted a non-canonical payload")
	}
	if _, err := normalizeTesseraOrigin("https://Tessera.example"); err == nil {
		t.Fatal("accepted a non-canonical origin")
	}
	if _, err := normalizeTesseraOrigin("https://tessera.example/path"); err == nil {
		t.Fatal("accepted an origin with a path")
	}
}

func TestTesseraConfirmationPhraseReadsTheWholeLine(t *testing.T) {
	values := make([]string, 18)
	values[0] = "tessera:assignment-confirmation:v1"
	var output bytes.Buffer
	if err := tesseraDisplayAndConfirmIO(strings.NewReader("CONFIRM ASSIGNMENT\n"), &output, values); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Type CONFIRM ASSIGNMENT to sign") {
		t.Fatalf("missing confirmation prompt: %s", output.String())
	}
}

func TestTesseraCapabilitiesRequireAnAttestedCommit(t *testing.T) {
	saved := releaseCommit
	t.Cleanup(func() { releaseCommit = saved })
	releaseCommit = ""
	if err := runTesseraCapabilities([]string{"--json"}); err == nil {
		t.Fatal("accepted an unpinned development build")
	}
}
