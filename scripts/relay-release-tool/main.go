// Command relay-release-tool creates and verifies the deterministic metadata
// used by Relay release packages. It is intentionally dependency-free so the
// release process does not add a second software supply chain.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	manifestSchema      = "relay-build-package/v1"
	expectedModulePath  = "github.com/zksecurity/relay"
	productionGoVersion = "go1.26.5"
	buildFlags          = "-trimpath -buildvcs=true -ldflags=-buildid="
)

var coreFiles = []string{
	"build-flags.txt",
	"build-mode.txt",
	"checksums.sha256",
	"go-build-info.txt",
	"relay",
	"sbom.cdx.json",
	"signed-tag-object.txt",
	"signed-tag-signer-fingerprint.txt",
	"signed-tag-status.txt",
	"signed-tag.txt",
	"source-checksums.sha256",
	"source-commit.txt",
	"source-date-epoch.txt",
	"test-status.txt",
	"toolchain-checksums.sha256",
}

type packageManifest struct {
	Schema               string         `json:"schema"`
	Mode                 string         `json:"mode"`
	SourceCommit         string         `json:"source_commit"`
	SourceDateEpoch      int64          `json:"source_date_epoch"`
	SignedTag            string         `json:"signed_tag"`
	SignedTagObject      string         `json:"signed_tag_object"`
	TagSignerFingerprint string         `json:"tag_signer_fingerprint"`
	GoVersion            string         `json:"go_version"`
	BuildFlags           string         `json:"build_flags"`
	Files                []manifestFile `json:"files"`
}

type manifestFile struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type bom struct {
	BOMFormat   string      `json:"bomFormat"`
	SpecVersion string      `json:"specVersion"`
	Version     int         `json:"version"`
	Metadata    bomMetadata `json:"metadata"`
	Components  []component `json:"components"`
}

type bomMetadata struct {
	Tools      bomTools   `json:"tools"`
	Component  component  `json:"component"`
	Properties []property `json:"properties"`
}

type bomTools struct {
	Components []component `json:"components"`
}

type component struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	BOMRef  string `json:"bom-ref,omitempty"`
	PURL    string `json:"purl,omitempty"`
}

type property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type verifyOptions struct {
	dir                  string
	mode                 string
	commit               string
	tag                  string
	tagObject            string
	tagSignerFingerprint string
	trustedPublicKey     string
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = runKeygen(os.Args[2:])
	case "sbom":
		err = runSBOM(os.Args[2:])
	case "manifest":
		err = runManifest(os.Args[2:])
	case "sign":
		err = runSign(os.Args[2:])
	case "verify":
		err = runVerify(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: relay-release-tool keygen|sbom|manifest|sign|verify [flags]")
	os.Exit(2)
}

func runKeygen(args []string) error {
	flags := flag.NewFlagSet("keygen", flag.ContinueOnError)
	privateKeyOut := flags.String("private-key-out", "", "fresh Ed25519 seed output")
	publicKeyOut := flags.String("public-key-out", "", "fresh Ed25519 public-key output")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *privateKeyOut == "" || *publicKeyOut == "" || *privateKeyOut == *publicKeyOut {
		return errors.New("usage: relay-release-tool keygen --private-key-out FILE --public-key-out FILE")
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate Ed25519 build-signing key: %w", err)
	}
	defer clear(privateKey)
	seed := privateKey.Seed()
	defer clear(seed)
	if err := writeFresh(*privateKeyOut, []byte(hex.EncodeToString(seed)+"\n"), 0o600); err != nil {
		return err
	}
	return writeFresh(*publicKeyOut, []byte(hex.EncodeToString(publicKey)+"\n"), 0o600)
}

func runSBOM(args []string) error {
	flags := flag.NewFlagSet("sbom", flag.ContinueOnError)
	binary := flags.String("binary", "", "Relay executable")
	out := flags.String("out", "", "fresh CycloneDX output")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *binary == "" || *out == "" {
		return errors.New("usage: relay-release-tool sbom --binary FILE --out FILE")
	}
	info, err := buildinfo.ReadFile(*binary)
	if err != nil {
		return fmt.Errorf("read binary build information: %w", err)
	}
	commit, err := validateBuildInfo(info, "")
	if err != nil {
		return err
	}
	if len(info.Deps) != 0 {
		return fmt.Errorf("Relay binary unexpectedly links %d third-party modules", len(info.Deps))
	}
	result := bom{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.5",
		Version:     1,
		Metadata: bomMetadata{
			Tools: bomTools{Components: []component{{
				Type:    "application",
				Name:    "relay/scripts/relay-release-tool",
				Version: commit,
			}}},
			Component: component{
				Type:    "application",
				Name:    "relay",
				Version: commit,
				BOMRef:  "pkg:golang/github.com/zksecurity/relay@" + commit,
				PURL:    "pkg:golang/github.com/zksecurity/relay@" + commit,
			},
			Properties: []property{
				{Name: "relay:go-version", Value: info.GoVersion},
				{Name: "relay:source-commit", Value: commit},
				{Name: "relay:vcs-modified", Value: "false"},
			},
		},
		Components: []component{},
	}
	return writeJSONFresh(*out, result)
}

func runManifest(args []string) error {
	flags := flag.NewFlagSet("manifest", flag.ContinueOnError)
	dir := flags.String("dir", "", "release staging directory")
	out := flags.String("out", "", "fresh manifest output")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *dir == "" || *out == "" {
		return errors.New("usage: relay-release-tool manifest --dir DIR --out FILE")
	}
	if err := validateRealDirectory(*dir); err != nil {
		return err
	}
	actual, err := directoryEntries(*dir)
	if err != nil {
		return err
	}
	expected := append([]string(nil), coreFiles...)
	sort.Strings(expected)
	if !equalStrings(actual, expected) {
		return fmt.Errorf("staging directory has unexpected entries: got %v, want %v", actual, expected)
	}
	mode, err := readText(*dir, "build-mode.txt")
	if err != nil {
		return err
	}
	if mode != "production" && mode != "rehearsal" {
		return fmt.Errorf("invalid build mode %q", mode)
	}
	commit, err := readText(*dir, "source-commit.txt")
	if err != nil {
		return err
	}
	if err := validateCommit(commit); err != nil {
		return err
	}
	epochText, err := readText(*dir, "source-date-epoch.txt")
	if err != nil {
		return err
	}
	epoch, err := strconv.ParseInt(epochText, 10, 64)
	if err != nil || epoch <= 0 {
		return fmt.Errorf("invalid source date epoch %q", epochText)
	}
	tag, err := readText(*dir, "signed-tag.txt")
	if err != nil {
		return err
	}
	tagObject, err := readText(*dir, "signed-tag-object.txt")
	if err != nil {
		return err
	}
	fingerprint, err := readText(*dir, "signed-tag-signer-fingerprint.txt")
	if err != nil {
		return err
	}
	flagsText, err := readText(*dir, "build-flags.txt")
	if err != nil {
		return err
	}
	if flagsText != buildFlags {
		return fmt.Errorf("build flags are %q, want %q", flagsText, buildFlags)
	}
	info, err := buildinfo.ReadFile(filepath.Join(*dir, "relay"))
	if err != nil {
		return err
	}
	if _, err := validateBuildInfo(info, commit); err != nil {
		return err
	}
	if err := validateBuildTime(info, epoch); err != nil {
		return err
	}
	files := make([]manifestFile, 0, len(coreFiles))
	for _, name := range coreFiles {
		size, digest, err := hashRegular(filepath.Join(*dir, name))
		if err != nil {
			return err
		}
		files = append(files, manifestFile{Name: name, Size: size, SHA256: digest})
	}
	manifest := packageManifest{
		Schema:               manifestSchema,
		Mode:                 mode,
		SourceCommit:         commit,
		SourceDateEpoch:      epoch,
		SignedTag:            tag,
		SignedTagObject:      tagObject,
		TagSignerFingerprint: fingerprint,
		GoVersion:            info.GoVersion,
		BuildFlags:           flagsText,
		Files:                files,
	}
	return writeJSONFresh(*out, manifest)
}

func runSign(args []string) error {
	flags := flag.NewFlagSet("sign", flag.ContinueOnError)
	input := flags.String("input", "", "exact manifest to sign")
	privateKeyPath := flags.String("private-key", "", "Ed25519 seed or private key in hex")
	signatureOut := flags.String("signature-out", "", "fresh detached signature output")
	publicKeyOut := flags.String("public-key-out", "", "fresh public-key output")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *input == "" || *privateKeyPath == "" ||
		*signatureOut == "" || *publicKeyOut == "" || *signatureOut == *publicKeyOut {
		return errors.New("usage: relay-release-tool sign --input FILE --private-key KEY --signature-out FILE --public-key-out FILE")
	}
	data, err := readBoundedRegular(*input, false, 64<<20)
	if err != nil {
		return err
	}
	keyHex, err := readBoundedRegular(*privateKeyPath, true, 1024)
	if err != nil {
		return err
	}
	defer clear(keyHex)
	raw, err := hex.DecodeString(strings.TrimSpace(string(keyHex)))
	if err != nil {
		return fmt.Errorf("decode Ed25519 private key: %w", err)
	}
	defer clear(raw)
	var privateKey ed25519.PrivateKey
	switch len(raw) {
	case ed25519.SeedSize:
		privateKey = ed25519.NewKeyFromSeed(raw)
	case ed25519.PrivateKeySize:
		privateKey = ed25519.NewKeyFromSeed(raw[:ed25519.SeedSize])
		if !bytes.Equal(raw, privateKey) {
			return errors.New("Ed25519 private-key public half does not match its seed")
		}
	default:
		return fmt.Errorf("Ed25519 key is %d bytes, want %d-byte seed or %d-byte private key", len(raw), ed25519.SeedSize, ed25519.PrivateKeySize)
	}
	defer clear(privateKey)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	signature := ed25519.Sign(privateKey, data)
	if err := writeFresh(*signatureOut, []byte(hex.EncodeToString(signature)+"\n"), 0o600); err != nil {
		return err
	}
	return writeFresh(*publicKeyOut, []byte(hex.EncodeToString(publicKey)+"\n"), 0o600)
}

func runVerify(args []string) error {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	opts := verifyOptions{}
	flags.StringVar(&opts.dir, "dir", "", "release directory")
	flags.StringVar(&opts.mode, "mode", "", "production or rehearsal")
	flags.StringVar(&opts.commit, "commit", "", "expected source commit")
	flags.StringVar(&opts.tag, "tag", "", "expected signed tag or none")
	flags.StringVar(&opts.tagObject, "tag-object", "", "expected signed tag object or none")
	flags.StringVar(&opts.tagSignerFingerprint, "tag-signer-fingerprint", "", "expected signer fingerprint or none")
	flags.StringVar(&opts.trustedPublicKey, "trusted-build-public-key-file", "", "trusted Ed25519 public key or none")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || opts.dir == "" || opts.mode == "" || opts.commit == "" ||
		opts.tag == "" || opts.tagObject == "" || opts.tagSignerFingerprint == "" || opts.trustedPublicKey == "" {
		return errors.New("verify requires --dir, --mode, --commit, --tag, --tag-object, --tag-signer-fingerprint, and --trusted-build-public-key-file")
	}
	return verifyPackage(opts)
}

func verifyPackage(opts verifyOptions) error {
	if err := validateRealDirectory(opts.dir); err != nil {
		return err
	}
	if err := validateCommit(opts.commit); err != nil {
		return err
	}
	if opts.mode != "production" && opts.mode != "rehearsal" {
		return fmt.Errorf("invalid expected mode %q", opts.mode)
	}
	expectedEntries := append([]string(nil), coreFiles...)
	expectedEntries = append(expectedEntries, "build-package-manifest.json", "build-package-manifest.sha256")
	if opts.mode == "production" {
		if opts.tag == "none" || opts.tagObject == "none" || opts.tagSignerFingerprint == "none" || opts.trustedPublicKey == "none" {
			return errors.New("production verification requires tag and build-signing trust inputs")
		}
		expectedEntries = append(expectedEntries, "build-package-manifest-public-key.hex", "build-package-manifest.sig")
	} else if opts.tag != "none" || opts.tagObject != "none" || opts.tagSignerFingerprint != "none" || opts.trustedPublicKey != "none" {
		return errors.New("rehearsal verification requires all production trust inputs to be none")
	}
	sort.Strings(expectedEntries)
	actualEntries, err := directoryEntries(opts.dir)
	if err != nil {
		return err
	}
	if !equalStrings(actualEntries, expectedEntries) {
		return fmt.Errorf("release directory has unexpected entries: got %v, want %v", actualEntries, expectedEntries)
	}
	for _, name := range expectedEntries {
		info, err := os.Lstat(filepath.Join(opts.dir, name))
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("release entry is not a regular file: %s", name)
		}
		wantMode := fs.FileMode(0o444)
		if name == "relay" {
			wantMode = 0o555
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != wantMode {
			return fmt.Errorf("release entry %s has mode %03o, want %03o", name, info.Mode().Perm(), wantMode)
		}
	}
	manifestBytes, err := readBoundedRegular(filepath.Join(opts.dir, "build-package-manifest.json"), false, 64<<20)
	if err != nil {
		return err
	}
	if opts.mode == "production" {
		if err := verifyManifestSignature(opts.dir, opts.trustedPublicKey, manifestBytes); err != nil {
			return err
		}
	}
	var manifest packageManifest
	decoder := json.NewDecoder(bytes.NewReader(manifestBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return fmt.Errorf("decode package manifest: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("package manifest contains trailing JSON")
	}
	if manifest.Schema != manifestSchema || manifest.Mode != opts.mode ||
		manifest.SourceCommit != opts.commit || manifest.SignedTag != opts.tag ||
		manifest.SignedTagObject != opts.tagObject ||
		manifest.TagSignerFingerprint != opts.tagSignerFingerprint ||
		manifest.GoVersion != productionGoVersion || manifest.BuildFlags != buildFlags {
		return errors.New("package manifest metadata does not match the approved release inputs")
	}
	recordedEpoch, err := readText(opts.dir, "source-date-epoch.txt")
	if err != nil {
		return err
	}
	parsedEpoch, err := strconv.ParseInt(recordedEpoch, 10, 64)
	if err != nil || parsedEpoch <= 0 || manifest.SourceDateEpoch != parsedEpoch {
		return errors.New("package manifest source date does not match source-date-epoch.txt")
	}
	if len(manifest.Files) != len(coreFiles) {
		return fmt.Errorf("package manifest contains %d files, want %d", len(manifest.Files), len(coreFiles))
	}
	for index, name := range coreFiles {
		entry := manifest.Files[index]
		if entry.Name != name {
			return fmt.Errorf("package manifest file %d is %q, want %q", index, entry.Name, name)
		}
		size, digest, err := hashRegular(filepath.Join(opts.dir, name))
		if err != nil {
			return err
		}
		if entry.Size != size || entry.SHA256 != digest {
			return fmt.Errorf("package manifest does not match %s", name)
		}
	}
	manifestDigest := sha256.Sum256(manifestBytes)
	wantManifestChecksum := hex.EncodeToString(manifestDigest[:]) + "  build-package-manifest.json\n"
	if err := requireExactFile(filepath.Join(opts.dir, "build-package-manifest.sha256"), wantManifestChecksum); err != nil {
		return err
	}
	_, relayDigest, err := hashRegular(filepath.Join(opts.dir, "relay"))
	if err != nil {
		return err
	}
	if err := requireExactFile(filepath.Join(opts.dir, "checksums.sha256"), relayDigest+"  relay\n"); err != nil {
		return err
	}
	info, err := buildinfo.ReadFile(filepath.Join(opts.dir, "relay"))
	if err != nil {
		return err
	}
	if _, err := validateBuildInfo(info, opts.commit); err != nil {
		return err
	}
	if err := validateBuildTime(info, parsedEpoch); err != nil {
		return err
	}
	if err := verifyRecordedMetadata(opts); err != nil {
		return err
	}
	return verifySBOM(filepath.Join(opts.dir, "sbom.cdx.json"), opts.commit)
}

func verifyRecordedMetadata(opts verifyOptions) error {
	wants := map[string]string{
		"build-flags.txt":                   buildFlags,
		"build-mode.txt":                    opts.mode,
		"signed-tag.txt":                    opts.tag,
		"signed-tag-object.txt":             opts.tagObject,
		"signed-tag-signer-fingerprint.txt": opts.tagSignerFingerprint,
		"source-commit.txt":                 opts.commit,
		"test-status.txt":                   "go test ./...: passed",
	}
	if opts.mode == "production" {
		wants["signed-tag-status.txt"] = "verified"
	} else {
		wants["signed-tag-status.txt"] = "not-required-for-rehearsal"
	}
	for name, want := range wants {
		got, err := readText(opts.dir, name)
		if err != nil {
			return err
		}
		if got != want {
			return fmt.Errorf("%s is %q, want %q", name, got, want)
		}
	}
	epoch, err := readText(opts.dir, "source-date-epoch.txt")
	if err != nil {
		return err
	}
	if value, err := strconv.ParseInt(epoch, 10, 64); err != nil || value <= 0 {
		return fmt.Errorf("invalid source-date-epoch.txt value %q", epoch)
	}
	return nil
}

func verifyManifestSignature(dir, trustedPublicKeyPath string, manifest []byte) error {
	trustedHex, err := readBoundedRegular(trustedPublicKeyPath, false, 1024)
	if err != nil {
		return err
	}
	packageHex, err := readBoundedRegular(filepath.Join(dir, "build-package-manifest-public-key.hex"), false, 1024)
	if err != nil {
		return err
	}
	trusted := strings.TrimSpace(string(trustedHex))
	if trusted != strings.TrimSpace(string(packageHex)) {
		return errors.New("package build public key does not match the independently trusted key")
	}
	publicKey, err := hex.DecodeString(trusted)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return errors.New("trusted build public key is not a 32-byte Ed25519 key in hex")
	}
	signatureHex, err := readBoundedRegular(filepath.Join(dir, "build-package-manifest.sig"), false, 1024)
	if err != nil {
		return err
	}
	signature, err := hex.DecodeString(strings.TrimSpace(string(signatureHex)))
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("build package signature is not a 64-byte Ed25519 signature in hex")
	}
	if !ed25519.Verify(publicKey, manifest, signature) {
		return errors.New("build package manifest signature is invalid")
	}
	return nil
}

func validateBuildInfo(info *debug.BuildInfo, expectedCommit string) (string, error) {
	if info == nil {
		return "", errors.New("binary has no Go build information")
	}
	if info.GoVersion != productionGoVersion {
		return "", fmt.Errorf("binary Go version is %q, want %q", info.GoVersion, productionGoVersion)
	}
	if info.Main.Path != expectedModulePath {
		return "", fmt.Errorf("binary module path is %q, want %q", info.Main.Path, expectedModulePath)
	}
	wants := map[string]string{
		"-buildmode":   "exe",
		"-compiler":    "gc",
		"-trimpath":    "true",
		"CGO_ENABLED":  "0",
		"GOARCH":       "amd64",
		"GOOS":         "linux",
		"GOAMD64":      "v1",
		"vcs":          "git",
		"vcs.modified": "false",
	}
	for key, want := range wants {
		got, err := uniqueSetting(info.Settings, key)
		if err != nil {
			return "", err
		}
		if got != want {
			return "", fmt.Errorf("binary build setting %s is %q, want %q", key, got, want)
		}
	}
	commit, err := uniqueSetting(info.Settings, "vcs.revision")
	if err != nil {
		return "", err
	}
	if err := validateCommit(commit); err != nil {
		return "", err
	}
	if expectedCommit != "" && commit != expectedCommit {
		return "", fmt.Errorf("binary source commit is %q, want %q", commit, expectedCommit)
	}
	if len(info.Deps) != 0 {
		return "", fmt.Errorf("Relay binary unexpectedly links %d third-party modules", len(info.Deps))
	}
	return commit, nil
}

func validateBuildTime(info *debug.BuildInfo, expectedEpoch int64) error {
	value, err := uniqueSetting(info.Settings, "vcs.time")
	if err != nil {
		return err
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return fmt.Errorf("binary vcs.time is invalid: %w", err)
	}
	if parsed.Unix() != expectedEpoch {
		return fmt.Errorf("binary vcs.time is %d, want source epoch %d", parsed.Unix(), expectedEpoch)
	}
	return nil
}

func verifySBOM(path, commit string) error {
	data, err := readBoundedRegular(path, false, 16<<20)
	if err != nil {
		return err
	}
	var value bom
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return fmt.Errorf("decode SBOM: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("SBOM contains trailing JSON")
	}
	if value.BOMFormat != "CycloneDX" || value.SpecVersion != "1.5" || value.Version != 1 {
		return errors.New("SBOM is not exact CycloneDX 1.5")
	}
	if value.Metadata.Component.Name != "relay" || value.Metadata.Component.Version != commit {
		return errors.New("SBOM application identity does not match the release")
	}
	if value.Metadata.Component.Type != "application" ||
		value.Metadata.Component.BOMRef != "pkg:golang/github.com/zksecurity/relay@"+commit ||
		value.Metadata.Component.PURL != "pkg:golang/github.com/zksecurity/relay@"+commit {
		return errors.New("SBOM application coordinates do not match the release")
	}
	if len(value.Metadata.Tools.Components) != 1 ||
		value.Metadata.Tools.Components[0] != (component{
			Type: "application", Name: "relay/scripts/relay-release-tool", Version: commit,
		}) {
		return errors.New("SBOM generator identity does not match the release")
	}
	wantProperties := []property{
		{Name: "relay:go-version", Value: productionGoVersion},
		{Name: "relay:source-commit", Value: commit},
		{Name: "relay:vcs-modified", Value: "false"},
	}
	if len(value.Metadata.Properties) != len(wantProperties) {
		return errors.New("SBOM properties do not match the release")
	}
	for index := range wantProperties {
		if value.Metadata.Properties[index] != wantProperties[index] {
			return errors.New("SBOM properties do not match the release")
		}
	}
	if len(value.Components) != 0 {
		return errors.New("dependency-free Relay SBOM unexpectedly lists components")
	}
	return nil
}

func validateCommit(value string) error {
	if len(value) != 40 {
		return errors.New("source commit is not exactly 40 lowercase hexadecimal characters")
	}
	if _, err := hex.DecodeString(value); err != nil || value != strings.ToLower(value) || strings.Trim(value, "0") == "" {
		return errors.New("source commit is not exactly 40 lowercase hexadecimal characters")
	}
	return nil
}

func uniqueSetting(settings []debug.BuildSetting, key string) (string, error) {
	var value string
	found := false
	for _, setting := range settings {
		if setting.Key != key {
			continue
		}
		if found {
			return "", fmt.Errorf("binary build setting %q is duplicated", key)
		}
		value = setting.Value
		found = true
	}
	if !found || strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("binary build setting %q is missing", key)
	}
	return value, nil
}

func validateRealDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("path must be a real directory: %s", path)
	}
	return nil
}

func directoryEntries(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names, nil
}

func readText(dir, name string) (string, error) {
	data, err := readBoundedRegular(filepath.Join(dir, name), false, 1<<20)
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(data))
	if value == "" {
		return "", fmt.Errorf("%s is empty", name)
	}
	return value, nil
}

func readBoundedRegular(path string, secret bool, limit int64) ([]byte, error) {
	linkInfo, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !linkInfo.Mode().IsRegular() || linkInfo.Size() <= 0 || linkInfo.Size() > limit {
		return nil, fmt.Errorf("input must be a bounded non-empty regular file: %s", path)
	}
	if secret && runtime.GOOS != "windows" && linkInfo.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("private key has group/world permission bits")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || !os.SameFile(linkInfo, info) {
		return nil, fmt.Errorf("input changed while being opened: %s", path)
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != info.Size() {
		return nil, fmt.Errorf("input changed while being read: %s", path)
	}
	return data, nil
}

func hashRegular(path string) (int64, string, error) {
	linkInfo, err := os.Lstat(path)
	if err != nil {
		return 0, "", err
	}
	if !linkInfo.Mode().IsRegular() {
		return 0, "", fmt.Errorf("not a regular file: %s", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return 0, "", err
	}
	if !os.SameFile(linkInfo, info) {
		return 0, "", fmt.Errorf("file changed while being opened: %s", path)
	}
	hash := sha256.New()
	written, err := io.Copy(hash, file)
	if err != nil {
		return 0, "", err
	}
	if written != info.Size() {
		return 0, "", fmt.Errorf("file changed while being hashed: %s", path)
	}
	return written, hex.EncodeToString(hash.Sum(nil)), nil
}

func requireExactFile(path, want string) error {
	data, err := readBoundedRegular(path, false, 1<<20)
	if err != nil {
		return err
	}
	if string(data) != want {
		return fmt.Errorf("file does not contain the expected bytes: %s", path)
	}
	return nil
}

func writeJSONFresh(path string, value any) error {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return err
	}
	return writeFresh(path, buffer.Bytes(), 0o600)
}

func writeFresh(path string, data []byte, mode fs.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}
