package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Opt-in real AWS CLI test. A single multipart upload must acquire a different
// credential after its first part, using the actual expiring process provider.
// No AWS account, credentials, or network outside the Docker host is used.
func TestAWSLoginDockerMultipartProvider(t *testing.T) {
	image := os.Getenv("RELAY_AWS_LOGIN_TEST_IMAGE")
	binary := os.Getenv("RELAY_AWS_LOGIN_TEST_BINARY")
	if image == "" || binary == "" {
		t.Skip("set RELAY_AWS_LOGIN_TEST_IMAGE and RELAY_AWS_LOGIN_TEST_BINARY (Linux Relay)")
	}
	dir := t.TempDir()
	_ = os.Chmod(dir, 0700)
	lease := syntheticAWSLease(time.Now().Add(2 * time.Minute))
	current := filepath.Join(dir, "current.json")
	if err := saveJSONAtomic(current, lease); err != nil {
		t.Fatal(err)
	}
	config := awsLoginRuntimeConfig + "region = us-east-1\ns3 =\n    addressing_style = path\n    max_concurrent_requests = 1\n    multipart_threshold = 5MB\n    multipart_chunksize = 5MB\n"
	if err := os.WriteFile(filepath.Join(dir, "config"), []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	payload := filepath.Join(t.TempDir(), "payload")
	if err := os.WriteFile(payload, make([]byte, 12*1024*1024), 0600); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var keys []string
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		_, _ = io.Copy(io.Discard, r.Body)
		auth := r.Header.Get("Authorization")
		key := ""
		if _, after, ok := strings.Cut(auth, "Credential="); ok {
			key, _, _ = strings.Cut(after, "/")
		}
		mu.Lock()
		keys = append(keys, key)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/xml")
		switch {
		case r.Method == "POST" && r.URL.Query().Has("uploads"):
			fmt.Fprint(w, `<InitiateMultipartUploadResult><Bucket>test</Bucket><Key>object</Key><UploadId>test-upload</UploadId></InitiateMultipartUploadResult>`)
		case r.Method == "PUT":
			if r.URL.Query().Get("partNumber") == "1" {
				next := lease
				next.AccessKeyId = "ROTATED"
				if err := saveJSONAtomic(current, next); err != nil {
					t.Error(err)
				}
			}
			w.Header().Set("ETag", `"test-etag"`)
		case r.Method == "POST":
			fmt.Fprint(w, `<CompleteMultipartUploadResult><Location>http://example.test/object</Location><Bucket>test</Bucket><Key>object</Key><ETag>"test-etag"</ETag></CompleteMultipartUploadResult>`)
		default:
			t.Errorf("unexpected S3 request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(400)
		}
	}))
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	_ = server.Listener.Close()
	server.Listener = listener
	server.Start()
	defer server.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	args := []string{"run", "--rm", "--pull=never", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--add-host=host.docker.internal:host-gateway", "--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()), "--tmpfs=/tmp:rw,nosuid,nodev,size=64m,mode=1777", "--env=HOME=/tmp", "--env=AWS_EC2_METADATA_DISABLED=true", "--env=AWS_CONFIG_FILE=/credentials/aws-login/config", "--env=AWS_SHARED_CREDENTIALS_FILE=/nonexistent", "--env=AWS_PAGER=", "--mount", "type=bind,src=" + dir + ",dst=/credentials/aws-login,readonly", "--mount", "type=bind,src=" + binary + ",dst=/usr/local/bin/relay,readonly", "--mount", "type=bind,src=" + payload + ",dst=/payload,readonly", "--entrypoint=/usr/local/bin/aws", image, "--profile", "relay-coordinator", "--endpoint-url", fmt.Sprintf("http://host.docker.internal:%d", port), "s3", "cp", "/payload", "s3://test/object", "--no-progress"}
	cmd := exec.Command("docker", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("AWS multipart upload failed: %v\n%s", err, output)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(keys) < 5 || keys[0] != "TESTACCESS" || keys[1] != "TESTACCESS" {
		t.Fatalf("unexpected initial requests: %v", keys)
	}
	for _, key := range keys[2:] {
		if key != "ROTATED" {
			t.Fatalf("one long-lived upload failed to refresh credentials: %v", keys)
		}
	}
}
