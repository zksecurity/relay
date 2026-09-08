package main

// Tessera integration exports public setup artifacts and supports legacy local
// account-consent signatures. It does not replace protocol enrollments or signing.
import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const tesseraSignRequestSchema = "tessera-sign-request-v1"
const tesseraSignResponseSchema = "tessera-sign-response-v1"
const tesseraCapabilitiesSchema = "tessera-capabilities-v1"

var tesseraUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var tesseraHash = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var tesseraID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var tesseraHex = regexp.MustCompile(`^[0-9a-f]+$`)

type tesseraSignRequest struct {
	Schema     string `json:"schema"`
	PayloadB64 string `json:"payload_b64"`
}
type tesseraSignResponse struct {
	Schema       string `json:"schema"`
	PayloadB64   string `json:"payload_b64"`
	SignatureHex string `json:"signature_hex"`
}
type tesseraIdentity struct {
	ID           string `json:"id"`
	DisplayName  string `json:"display_name"`
	KeyID        string `json:"key_id"`
	PublicKeyHex string `json:"ed25519_public_key_hex"`
	Fingerprint  string `json:"public_key_fingerprint"`
}
type tesseraCapabilities struct {
	Schema          string   `json:"schema"`
	RelayCommit     string   `json:"relay_commit"`
	FileSchemas     []string `json:"file_schemas"`
	SigningPurposes []string `json:"signing_purposes"`
}

func runTessera(args []string) error {
	if len(args) == 0 {
		return errors.New("tessera requires capabilities, complete-setup, verify-setup, release-manifest, export-setup or confirm")
	}
	switch args[0] {
	case "release-manifest":
		return runSetupManifest(args[1:])
	case "complete-setup":
		return runSetupV2(args[1:], true)
	case "verify-setup":
		return runSetupV2(args[1:], false)
	case "capabilities":
		return runTesseraCapabilities(args[1:])
	case "confirm":
		return runTesseraConfirm(args[1:])
	case "export-setup":
		return runTesseraExport(args[1:])
	default:
		return fmt.Errorf("unknown tessera command %q", args[0])
	}
}

func runTesseraCapabilities(args []string) error {
	set := flag.NewFlagSet("tessera capabilities", flag.ContinueOnError)
	jsonOutput := set.Bool("json", false, "print machine-readable capabilities")
	if err := set.Parse(args); err != nil {
		return err
	}
	if !*jsonOutput || set.NArg() != 0 {
		return errors.New("usage: relay tessera capabilities --json")
	}
	commit := launcherCommit()
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(commit) {
		return errors.New("Tessera capabilities require an attested Relay release build with its source commit")
	}
	result := tesseraCapabilities{Schema: tesseraCapabilitiesSchema, RelayCommit: commit, FileSchemas: []string{"ceremony-setup-v2", "ceremony-software-manifest-v2", "tessera-bundle-v1", "tessera-draft-context-v1", tesseraSignRequestSchema, tesseraSignResponseSchema}, SigningPurposes: []string{"tessera:assignment-confirmation:v1", "tessera:account-recovery:v1"}}
	return json.NewEncoder(os.Stdout).Encode(result)
}

func runTesseraConfirm(args []string) error {
	set := flag.NewFlagSet("tessera confirm", flag.ContinueOnError)
	requestPath := set.String("request", "", "Tessera signing request")
	identityPath := set.String("identity", "", "public ceremony identity")
	keyPath := set.String("signing-key", "", "private 32-byte Ed25519 seed")
	out := set.String("out", "", "fresh Tessera signing response")
	if err := set.Parse(args); err != nil {
		return err
	}
	if set.NArg() != 0 || *requestPath == "" || *identityPath == "" || *keyPath == "" || *out == "" {
		return errors.New("--request, --identity, --signing-key and --out are required")
	}
	requestBytes, err := readTesseraRegularFile(*requestPath, 16*1024, false)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	var request tesseraSignRequest
	if err := tesseraDecodeExact(requestBytes, &request); err != nil {
		return fmt.Errorf("request: %w", err)
	}
	payload, values, err := tesseraPayload(request)
	if err != nil {
		return err
	}
	identityBytes, err := readTesseraRegularFile(*identityPath, 16*1024, false)
	if err != nil {
		return fmt.Errorf("identity: %w", err)
	}
	var identity tesseraIdentity
	if err := tesseraDecodeExact(identityBytes, &identity); err != nil {
		return fmt.Errorf("identity: %w", err)
	}
	publicKey, err := tesseraValidateIdentity(identity)
	if err != nil {
		return err
	}
	if values[10] != identity.ID || values[11] != hex.EncodeToString(publicKey) {
		return errors.New("request identity does not match the supplied public identity")
	}
	privateSeed, err := readTesseraSeed(*keyPath)
	if err != nil {
		return err
	}
	defer zeroTessera(privateSeed)
	privateKey := ed25519.NewKeyFromSeed(privateSeed)
	defer zeroTessera(privateKey)
	if !bytes.Equal(privateKey.Public().(ed25519.PublicKey), publicKey) {
		return errors.New("private signing key does not match supplied public identity")
	}
	if err := tesseraDisplayAndConfirm(values); err != nil {
		return err
	}
	response := tesseraSignResponse{Schema: tesseraSignResponseSchema, PayloadB64: request.PayloadB64, SignatureHex: hex.EncodeToString(ed25519.Sign(privateKey, payload))}
	output, err := json.Marshal(response)
	if err != nil {
		return err
	}
	output = append(output, '\n')
	if err := writeTesseraFresh(*out, output, 0o600); err != nil {
		return fmt.Errorf("response: %w", err)
	}
	fmt.Fprintf(os.Stdout, "Wrote Tessera %s response: %s\n", values[0], *out)
	return nil
}

func tesseraPayload(request tesseraSignRequest) ([]byte, []string, error) {
	if request.Schema != tesseraSignRequestSchema {
		return nil, nil, fmt.Errorf("request schema %q is unsupported", request.Schema)
	}
	if request.PayloadB64 == "" || len(request.PayloadB64) > 16*1024 {
		return nil, nil, errors.New("request payload is invalid")
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(request.PayloadB64)
	if err != nil || base64.StdEncoding.EncodeToString(payload) != request.PayloadB64 {
		return nil, nil, errors.New("request payload is not canonical base64")
	}
	var values []string
	if err := tesseraDecodeExact(payload, &values); err != nil {
		return nil, nil, fmt.Errorf("request payload: %w", err)
	}
	if len(values) != 18 {
		return nil, nil, errors.New("request payload must contain exactly 18 fields")
	}
	for _, value := range values {
		if strings.ContainsAny(value, "\\\"\n\r\t") || !tesseraASCII(value) {
			return nil, nil, errors.New("request payload contains invalid characters")
		}
	}
	if values[0] != "tessera:assignment-confirmation:v1" && values[0] != "tessera:account-recovery:v1" {
		return nil, nil, errors.New("request purpose is unsupported")
	}
	origin, err := normalizeTesseraOrigin(values[1])
	if err != nil || origin != values[1] {
		return nil, nil, errors.New("request origin is invalid")
	}
	for _, index := range []int{2, 6, 14} {
		if !tesseraUUID.MatchString(values[index]) {
			return nil, nil, errors.New("request UUID is invalid")
		}
	}
	for _, index := range []int{3, 4, 5} {
		if !tesseraHash.MatchString(values[index]) {
			return nil, nil, errors.New("request digest is invalid")
		}
	}
	if values[7] == "0" || !regexp.MustCompile(`^[1-9][0-9]{0,9}$`).MatchString(values[7]) || !tesseraID.MatchString(values[10]) || !tesseraHex.MatchString(values[11]) || len(values[11]) != 64 || !tesseraHex.MatchString(values[12]) || len(values[12]) != 64 || !tesseraHex.MatchString(values[15]) || len(values[15]) != 64 {
		return nil, nil, errors.New("request identity or binding is invalid")
	}
	if values[13] != "" && (!tesseraHex.MatchString(values[13]) || len(values[13]) != 64) {
		return nil, nil, errors.New("request previous account binding is invalid")
	}
	if values[8] != "coordinator" && values[8] != "participant" && values[8] != "auditor" && values[8] != "release-signer" && values[8] != "witness" && values[8] != "mirror" {
		return nil, nil, errors.New("request role is invalid")
	}
	if values[9] != "" && values[9] != "phase1" && values[9] != "phase2" && values[9] != "phase1,phase2" {
		return nil, nil, errors.New("request phases are invalid")
	}
	issued, err := time.Parse(time.RFC3339, values[16])
	if err != nil || issued.Format("2006-01-02T15:04:05Z") != values[16] {
		return nil, nil, errors.New("request issued time is invalid")
	}
	expires, err := time.Parse(time.RFC3339, values[17])
	if err != nil || expires.Sub(issued) != 24*time.Hour || expires.Format("2006-01-02T15:04:05Z") != values[17] {
		return nil, nil, errors.New("request expiry is invalid")
	}
	canonical, _ := json.Marshal(values)
	if !bytes.Equal(canonical, payload) {
		return nil, nil, errors.New("request payload is not canonical")
	}
	return payload, values, nil
}

func tesseraDecodeExact(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if token, err := decoder.Token(); err != io.EOF || token != nil {
		return errors.New("trailing JSON data")
	}
	canonical, err := json.Marshal(target)
	if err != nil {
		return err
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		return err
	}
	// The canonical field order rejects duplicate keys after decoding. Formatting
	// outside the signed payload is allowed so public request files stay readable.
	if !bytes.Equal(canonical, compact.Bytes()) {
		return errors.New("JSON is not canonical")
	}
	return nil
}
func tesseraASCII(value string) bool {
	for _, r := range value {
		if r < 0x20 || r > 0x7e {
			return false
		}
	}
	return true
}
func normalizeTesseraOrigin(value string) (string, error) {
	parsed, err := url.Parse(value)
	if err != nil {
		return "", err
	}
	if parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.Opaque != "" {
		return "", errors.New("HTTPS required")
	}
	if parsed.Host != strings.ToLower(parsed.Host) || parsed.Port() == "443" {
		return "", errors.New("origin is not canonical")
	}
	return parsed.String(), nil
}
func tesseraValidateIdentity(identity tesseraIdentity) (ed25519.PublicKey, error) {
	if !tesseraID.MatchString(identity.ID) || !tesseraID.MatchString(identity.KeyID) || identity.DisplayName == "" || len(identity.DisplayName) > 120 || !tesseraHex.MatchString(identity.PublicKeyHex) || len(identity.PublicKeyHex) != 64 {
		return nil, errors.New("public identity is invalid")
	}
	publicKey, _ := hex.DecodeString(identity.PublicKeyHex)
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, errors.New("public identity key is invalid")
	}
	sum := sha256.Sum256(publicKey)
	if identity.Fingerprint != "sha256:"+hex.EncodeToString(sum[:]) {
		return nil, errors.New("public identity fingerprint mismatch")
	}
	return ed25519.PublicKey(publicKey), nil
}
func readTesseraRegularFile(path string, limit int64, secret bool) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("must be a regular file")
	}
	if info.Size() > limit {
		return nil, errors.New("file is too large")
	}
	if secret && info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("private signing key permissions must be 0600 or stricter")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) || (secret && opened.Mode().Perm()&0o077 != 0) {
		return nil, errors.New("input changed while opening it")
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, errors.New("file is too large")
	}
	return raw, nil
}
func readTesseraSeed(path string) ([]byte, error) {
	raw, err := readTesseraRegularFile(path, 128, true)
	if err != nil {
		return nil, fmt.Errorf("signing key: %w", err)
	}
	value := strings.TrimSuffix(string(raw), "\n")
	if strings.ContainsAny(value, "\r\n") || !tesseraHex.MatchString(value) || len(value) != ed25519.SeedSize*2 {
		return nil, errors.New("signing key must be exactly one 32-byte hex seed")
	}
	seed, _ := hex.DecodeString(value)
	return seed, nil
}
func writeTesseraFresh(path string, content []byte, mode os.FileMode) error {
	if filepath.Clean(path) != path {
		return errors.New("output path must be clean")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}
func zeroTessera(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
func tesseraDisplayAndConfirm(values []string) error {
	return tesseraDisplayAndConfirmIO(os.Stdin, os.Stdout, values)
}

func tesseraDisplayAndConfirmIO(input io.Reader, output io.Writer, values []string) error {
	phrase := "CONFIRM ASSIGNMENT"
	label := "Confirm Tessera assignment"
	if values[0] == "tessera:account-recovery:v1" {
		phrase = "CONFIRM ACCOUNT RECOVERY"
		label = "Confirm Tessera account recovery"
	}
	fmt.Fprintf(output, "%s\nSite: %s\nCeremony: %s\nDefinition: %s\nBundle: %s\nRole/phases: %s / %s\nIdentity: %s\nPublic key: %s\nAccount binding: %s\n", label, values[1], values[3], values[4], values[5], values[8], values[9], values[10], values[11], values[12])
	if values[13] != "" {
		fmt.Fprintf(output, "Previous account binding: %s\n", values[13])
	}
	fmt.Fprintf(output, "Type %s to sign: ", phrase)
	typed, err := bufio.NewReader(input).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if strings.TrimSuffix(typed, "\n") != phrase {
		return errors.New("confirmation declined")
	}
	return nil
}
