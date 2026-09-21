package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/zksecurity/relay/internal/access"
	"github.com/zksecurity/relay/internal/teststore"
)

func TestUpgradeLocalStorageGrantScope(t *testing.T) {
	s := teststore.New()
	s.Endpoint = "https://local.test"
	s.ParentKey = strings.Repeat("1", 32)
	s.ParentSecret = strings.Repeat("2", 64)
	s.Account = strings.Repeat("3", 32)
	c := access.StorageConfig{Endpoint: s.Endpoint, AccountID: s.Account, ParentAccessKeyID: s.ParentKey, InboxBucket: "inbox"}
	grant, _, err := issueR2Locally(c, "allowed/", time.Hour, time.Now(), s.ParentSecret)
	if err != nil {
		t.Fatal(err)
	}
	request := func(bucket, key string, cred access.SessionCredentials) teststore.Request {
		return teststore.Request{Args: []string{"--endpoint-url", s.Endpoint, "s3api", "put-object", "--bucket", bucket, "--key", key, "--if-none-match", "*"}, Key: cred.AccessKeyID, Secret: cred.SecretAccessKey, Token: cred.SessionToken}
	}
	if r := s.Execute(request("inbox", "allowed/a", grant)); r.Error != "" {
		t.Fatal(r.Error)
	}
	for _, pair := range [][2]string{{"published", "allowed/a"}, {"inbox", "other/a"}, {"inbox", "allowed/../a"}} {
		if r := s.Execute(request(pair[0], pair[1], grant)); r.Error == "" {
			t.Fatal("scope escape", pair)
		}
	}
	expired, _, err := issueR2Locally(c, "allowed/", time.Second, time.Now().Add(-time.Minute), s.ParentSecret)
	if err != nil {
		t.Fatal(err)
	}
	if r := s.Execute(request("inbox", "allowed/b", expired)); r.Error != "AccessDenied" {
		t.Fatal(r)
	}
	grant.SecretAccessKey = "wrong"
	if r := s.Execute(request("inbox", "allowed/b", grant)); r.Error != "AccessDenied" {
		t.Fatal(r)
	}
}

// No cloud credentials, provider calls, OS trust changes or Docker socket mounts.
// Only the online storage subprocess is replaced. Cryptographic images stay exact.
func TestUpgradeLocalTwoPhaseJourney(t *testing.T) {
	if os.Getenv("RELAY_UPGRADE_LOCAL_STORAGE") != "1" {
		t.Skip("opt-in local storage ceremony")
	}
	f := realUpgradeFixture(t)
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	s := teststore.New()
	randomHex := func(n int) string {
		b := make([]byte, n)
		if _, e := rand.Read(b); e != nil {
			t.Fatal(e)
		}
		return hex.EncodeToString(b)
	}
	s.CoordinatorKey, s.CoordinatorSecret = randomHex(16), randomHex(32)
	s.ParentKey, s.ParentSecret, s.Account = randomHex(16), randomHex(32), strings.Repeat("1", 32)
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Relay local test only"}, DNSNames: []string{"host.docker.internal", "localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(4 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewUnstartedServer(s)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	s.Endpoint = strings.Replace(server.URL, "127.0.0.1", "host.docker.internal", 1)
	ca := filepath.Join(root, "ca.pem")
	if e := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); e != nil {
		t.Fatal(e)
	}
	pool, e := x509.SystemCertPool()
	if e != nil {
		t.Fatal(e)
	}
	pool.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	dialer := &net.Dialer{Timeout: 30 * time.Second}
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		addr = strings.Replace(addr, "host.docker.internal:", "127.0.0.1:", 1)
		return dialer.DialContext(ctx, network, addr)
	}
	oldTransport, oldClient := http.DefaultTransport, http.DefaultClient
	http.DefaultTransport = transport
	http.DefaultClient = &http.Client{Transport: transport}
	t.Cleanup(func() {
		http.DefaultTransport, http.DefaultClient = oldTransport, oldClient
		transport.CloseIdleConnections()
	})
	bin := filepath.Join(root, "bin")
	if e := os.Mkdir(bin, 0700); e != nil {
		t.Fatal(e)
	}
	docker, e := exec.LookPath("docker")
	if e != nil {
		t.Fatal(e)
	}
	build := func(out, goos string) {
		module, err := exec.Command("go", "env", "GOMOD").Output()
		if err != nil || !filepath.IsAbs(strings.TrimSpace(string(module))) {
			t.Fatal("local adapter requires the reviewed module checkout", err)
		}
		c := exec.Command("go", "build", "-o", out, "./cmd/relay/testdata/localaws")
		c.Dir = filepath.Dir(strings.TrimSpace(string(module)))
		c.Env = append(os.Environ(), "GOOS="+goos, "GOARCH="+runtime.GOARCH, "CGO_ENABLED=0")
		if b, e := c.CombinedOutput(); e != nil {
			t.Fatalf("build local adapter: %v %s", e, b)
		}
	}
	linuxAWS := filepath.Join(root, "aws-linux")
	build(linuxAWS, "linux")
	build(filepath.Join(bin, "aws"), runtime.GOOS)
	quote := func(v string) string { return "'" + strings.ReplaceAll(v, "'", "'\\''") + "'" }
	// Fixed exact online-image matches; no injection into signer/contributor,
	// no mounts from user directories, and no real AWS executable fallback.
	script := "#!/bin/bash\nset -euo pipefail\nargs=(\"$@\")\nfor ((i=0;i<${#args[@]};i++)); do\n if [[ ${args[i]} == run ]]; then\n  online=false\n  for a in \"${args[@]}\"; do\n   if [[ $a == " + quote(f.request.Declaration.OriginalImage) + " || $a == " + quote(f.request.Declaration.OnlineImage) + " ]]; then online=true; fi\n  done\n  if $online; then\n   extra=(--mount " + quote("type=bind,src="+linuxAWS+",dst=/usr/local/bin/aws,readonly") + " --mount " + quote("type=bind,src="+ca+",dst=/local-ca.pem,readonly") + " --env LOCAL_STORE_CA=/local-ca.pem --env SSL_CERT_FILE=/local-ca.pem --env " + quote("LOCAL_STORE_URL="+s.Endpoint) + ")\n   args=(\"${args[@]:0:i+1}\" \"${extra[@]}\" \"${args[@]:i+1}\")\n  fi\n  break\n fi\ndone\nexec " + quote(docker) + " \"${args[@]}\"\n"
	if e := os.WriteFile(filepath.Join(bin, "docker"), []byte(script), 0700); e != nil {
		t.Fatal(e)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("LOCAL_STORE_URL", server.URL)
	t.Setenv("LOCAL_STORE_CA", ca)
	config := access.StorageConfig{Schema: access.StorageConfigSchema, Provider: "r2", CeremonyID: "sha256:" + strings.Repeat("0", 64), Endpoint: s.Endpoint, Region: "auto", AccountID: s.Account, ParentAccessKeyID: s.ParentKey, PublishedBucket: "published", PublishedBaseURL: s.Endpoint + "/published", InboxBucket: "inbox", CoordinatorProfile: "local-test", CeremonyPath: "/work/ceremony/public/ceremony.json", CeremonySignature: "/work/ceremony/public/ceremony.sig", CoordinatorPublicKey: "/trust/setup-coordinator.hex", CeremonyBinary: dockerCeremonyBinary}
	configPath := filepath.Join(root, "storage.json")
	if e := writeJSONNoReplace(configPath, config, 0600); e != nil {
		t.Fatal(e)
	}
	credentials := filepath.Join(root, "aws")
	parent := filepath.Join(root, "parent")
	control := filepath.Join(root, "control")
	for p, v := range map[string]string{credentials: fmt.Sprintf("[local-test]\naws_access_key_id = %s\naws_secret_access_key = %s\n", s.CoordinatorKey, s.CoordinatorSecret), parent: s.ParentSecret, control: "local-test-unused"} {
		if e := os.WriteFile(p, []byte(v), 0600); e != nil {
			t.Fatal(e)
		}
	}
	// Exact Linux binary is a permitted companion artifact, never executed on macOS.
	copied := filepath.Join(root, "mpc-ceremony-linux")
	out, e := exec.Command(docker, "create", f.request.Declaration.SigningImage).Output()
	if e != nil {
		t.Fatal(e)
	}
	id := strings.TrimSpace(string(out))
	if !validContainerID(id) {
		t.Fatal("bad fixture container ID")
	}
	defer exec.Command(docker, "rm", id).Run()
	if b, e := exec.Command(docker, "cp", id+":"+dockerCeremonyBinary, copied).CombinedOutput(); e != nil {
		t.Fatalf("extract fixture binary: %v %s", e, b)
	}
	h, e := setupFileHash(copied)
	if e != nil || "sha256:"+h != f.request.Declaration.ProofToolSHA256 {
		t.Fatal("original binary mismatch", e)
	}
	for k, v := range map[string]string{"RELAY_V4_LIVE_R2_CONFIG": configPath, "RELAY_V4_LIVE_R2_CREDENTIALS": credentials, "RELAY_V4_LIVE_R2_PARENT": parent, "RELAY_V4_LIVE_R2_CONTROL": control, "RELAY_V4_LIVE_PROOF_BINARY": copied} {
		t.Setenv(k, v)
	}
	runUpgradeTwoPhaseJourney(t, f, true)
}
