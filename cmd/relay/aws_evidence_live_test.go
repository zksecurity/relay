package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Reuses only public artifacts from a completed tiny rehearsal. Issuance,
// upload and receipt run in separate containers; upload gets no issuer login
// or signing key. This is transport coverage, not independent human operation.
func TestAWSLiveRoleEvidenceHandoffs(t *testing.T) {
	if os.Getenv("RELAY_AWS_EVIDENCE_APPROVED") != "1" {
		t.Skip("explicit dedicated-account cloud handoff approval required")
	}
	root := os.Getenv("RELAY_AWS_PUBLIC_FIXTURE")
	if !filepath.IsAbs(root) {
		t.Fatal("absolute public rehearsal fixture required")
	}
	client := osDockerCommandClient{binary: "docker"}
	_, endpoint, err := resolveDockerEndpoint(client)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateLocalDockerEndpoint(endpoint); err != nil {
		t.Fatal(err)
	}
	roles := []string{"witness", "mirror", "auditor", "release"}
	stages := []string{"issue", "upload", "receive"}
	if os.Getenv("RELAY_AWS_EVIDENCE_RECEIVE_KEY") != "" {
		roles = []string{"release"}
		stages = []string{"verify-release"}
	}
	for _, role := range roles {
		t.Run(role, func(t *testing.T) {
			handoff := privateRoleTestDir(t)
			for _, stage := range stages {
				args := []string{"run", "--rm", "--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()), "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges=true", "--ulimit", "core=0:0", "--log-driver", "none", "--tmpfs", "/tmp:rw,nosuid,nodev,mode=1777", "--env", "HOME=/tmp", "--env", "AWS_EC2_METADATA_DISABLED=true", "--env", "RELAY_AWS_EVIDENCE_CHILD=" + stage, "--env", "RELAY_TEST_EVIDENCE_ROLE=" + role, "--env", "RELAY_AWS_LIVE_EXPECTED_ACCOUNT=" + os.Getenv("RELAY_AWS_LIVE_EXPECTED_ACCOUNT")}
				for _, mount := range []struct{ src, dst string }{
					{filepath.Join(root, "ceremony/public"), "/work/ceremony/public"},
					{filepath.Join(root, "ceremony/public"), "/trust"},
					{filepath.Join(root, "ceremony/config/relay-storage.json"), "/work/ceremony/config/relay-storage.json"},
					{filepath.Join(root, "release"), "/work/release"},
					{filepath.Join(root, "auditor-01.json"), "/work/auditor-01.json"},
					{filepath.Join(root, "auditor-01.sig"), "/work/auditor-01.sig"},
					{os.Getenv("RELAY_AWS_TEST_BINARY"), "/tests"},
				} {
					args = append(args, "--mount", "type=bind,src="+mount.src+",dst="+mount.dst+",readonly")
				}
				args = append(args, "--mount", "type=bind,src="+handoff+",dst=/handoff")
				if key := os.Getenv("RELAY_AWS_EVIDENCE_RECEIVE_KEY"); key != "" {
					args = append(args, "--env", "RELAY_AWS_EVIDENCE_RECEIVE_KEY="+key)
				}
				if stage != "upload" {
					args = append(args, "--mount", "type=bind,src="+freshAWSLiveCredentials(t)+",dst=/credentials,readonly", "--env", "AWS_SHARED_CREDENTIALS_FILE=/credentials")
				}
				args = append(args, "--entrypoint", "/tests", os.Getenv("RELAY_ROLE_ONLINE_IMAGE"), "-test.run", "^TestAWSLiveRoleEvidenceChild$", "-test.v")
				if err := client.BindHost(endpoint).Attached(os.Stdout, os.Stderr, args...); err != nil {
					t.Fatal(stage, "failed")
				}
			}
		})
	}
}

func TestAWSLiveRoleEvidenceChild(t *testing.T) {
	stage := os.Getenv("RELAY_AWS_EVIDENCE_CHILD")
	if stage == "" {
		t.Skip("cloud handoff child only")
	}
	role := os.Getenv("RELAY_TEST_EVIDENCE_ROLE")
	identities := map[string]string{"witness": "witness-01", "mirror": "mirror-01", "auditor": "auditor-01", "release": "release-signer"}
	id, ok := identities[role]
	if !ok {
		t.Fatal("unknown evidence role")
	}
	config, err := loadStorageConfig("/work/ceremony/config/relay-storage.json")
	if err != nil {
		t.Fatal(err)
	}
	requireAWSLiveConfiguration(t, config)
	if stage == "verify-release" {
		key := os.Getenv("RELAY_AWS_EVIDENCE_RECEIVE_KEY")
		client := coordinatorClient(config, config.InboxBucket)
		m, err := downloadSubmissionManifest(client, key)
		if err != nil {
			t.Fatal(err)
		}
		out := "/handoff/received"
		if err := receiveEvidence(config.CeremonyID, "release", key, out, m, client.GetSized); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("mpc-ceremony", "release", "verify", "--ceremony", config.CeremonyPath, "--ceremony-signature", config.CeremonySignature, "--coordinator-public-key-file", config.CoordinatorPublicKey, "--keys-dir", out, "--manifest-public-key-file", "/work/release/manifest-public-key.hex", "--signature-key-id", "release-signer-key")
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			t.Fatal("downloaded release failed cryptographic verification")
		}
		return
	}
	base := "/work/ceremony/public/operational/"
	grant := "/handoff/role.grant.json"
	sources := []string{}
	switch role {
	case "witness":
		sources = []string{base + "phase2/witnesses/" + id + ".json", base + "phase2/witnesses/" + id + ".sig"}
	case "mirror":
		sources = []string{base + "phase2/heads/0003/mirrors/" + id + ".json", base + "phase2/heads/0003/mirrors/" + id + ".sig"}
	case "auditor":
		sources = []string{"/work/auditor-01.json", "/work/auditor-01.sig"}
	}
	if stage == "issue" {
		err = runGrant([]string{"--storage", "/work/ceremony/config/relay-storage.json", "--role", role, "--identity", id, "--enrollment", base + "enrollments/" + id + ".json", "--enrollment-signature", base + "enrollments/" + id + ".sig", "--credential-ttl", "15m", "--minimum-remaining", "1m", "--out", grant})
	} else if stage == "upload" {
		args := []string{"--grant", grant}
		if role == "release" {
			args = append(args, "--dir", "/work/release")
		} else {
			for _, source := range sources {
				args = append(args, "--file", source)
			}
		}
		err = runSubmitEvidenceForRole(args, role)
	} else if stage == "receive" {
		client := coordinatorClient(config, config.InboxBucket)
		g, e := loadGrant(grant)
		if e != nil {
			t.Fatal(e)
		}
		objects, e := client.List(g.Prefix)
		if e != nil {
			t.Fatal(e)
		}
		found := false
		for _, key := range manifestKeys(objects) {
			m, e := downloadSubmissionManifest(client, key)
			if e != nil {
				// Earlier failed attempts/older layouts are not fresh completed
				// handoffs. At least one current valid manifest must still pass.
				continue
			}
			// Only the fresh grant's time window, not earlier fixture submissions.
			if m.CompletedAt < g.IssuedAt {
				continue
			}
			out := filepath.Join("/handoff", "received-"+m.AttemptID)
			if e := receiveEvidence(config.CeremonyID, role, key, out, m, client.GetSized); e != nil {
				t.Fatal(e)
			}
			for _, ref := range m.Files {
				source := "/work/release/" + ref.Name
				if role != "release" {
					source = ""
					for _, s := range sources {
						if filepath.Base(s) == ref.Name {
							source = s
						}
					}
				}
				want, e := regularFileRef(source, ref.Name)
				if e != nil || want != ref {
					t.Fatal("received bytes differ from verified public fixture")
				}
			}
			found = true
		}
		if !found {
			t.Fatal("no fresh role evidence received")
		}
		if role == "release" {
			t.Log("offline final signer's public bundle transported by upload-station lane; no signing key mounted")
		}
	} else {
		t.Fatal("unknown stage")
	}
	if err != nil {
		t.Fatal(strings.TrimSpace(stage) + " failed: " + err.Error())
	}
}
