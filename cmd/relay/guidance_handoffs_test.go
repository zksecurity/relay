package main

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zksecurity/relay/internal/access"
)

func prepareTestPublicStorage(t *testing.T, p *rolePreparer) {
	t.Helper()
	c := access.StorageConfig{Schema: access.StorageConfigSchema, Provider: "r2", CeremonyID: "sha256:" + strings.Repeat("1", 64), Endpoint: "https://account.invalid", AccountID: "account", ParentAccessKeyID: "parent", PublishedBucket: "published", PublishedBaseURL: "https://public.invalid", InboxBucket: "inbox", CoordinatorProfile: "coordinator", CeremonyPath: "/work/ceremony/public/ceremony.json", CeremonySignature: "/work/ceremony/public/ceremony.sig", CoordinatorPublicKey: "/trust/coordinator-public-key.hex", CeremonyBinary: "/usr/local/bin/mpc-ceremony"}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := writeJSONNoReplace(filepath.Join(p.d.Work, "ceremony/config/relay-storage.json"), c, 0600); err != nil {
		t.Fatal(err)
	}
}

func prepareTestEnrollmentHandoff(t *testing.T, p *rolePreparer) {
	t.Helper()
	dir := filepath.Join(p.d.Work, "my-enrollment")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"canonical.json", "enrollment.sig", "disclosure.txt"} {
		if err := writePublicTextOnce(filepath.Join(dir, name), "synthetic public fixture"); err != nil {
			t.Fatal(err)
		}
	}
}

func reportTestPublicHandoff(t *testing.T, p *rolePreparer, kind string) {
	t.Helper()
	p.ui.input = bufio.NewReader(strings.NewReader("1\n"))
	if err := p.reportPublicHandoff(kind); err != nil {
		t.Fatal(err)
	}
}

func TestGuidanceHandoffReportRechecksExactFiles(t *testing.T) {
	p := preparationFixture(t, "participant")
	prepareTestIdentity(t, p)
	p.ui.input = bufio.NewReader(strings.NewReader("2\n"))
	if err := p.reportPublicHandoff("identity"); err != nil {
		t.Fatal(err)
	}
	if p.publicHandoffReported("identity") {
		t.Fatal("waiting marked sent")
	}
	reportTestPublicHandoff(t, p, "identity")
	if !p.publicHandoffReported("identity") {
		t.Fatal("report missing")
	}
	var saved rolePreparation
	if err := setupReadJSON(p.path, &saved); err != nil {
		t.Fatal(err)
	}
	p.d = saved
	if !p.publicHandoffReported("identity") {
		t.Fatal("reopen lost report")
	}
	if err := os.WriteFile(filepath.Join(p.d.Keys, "identity.json"), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if p.publicHandoffReported("identity") {
		t.Fatal("changed artifact retained report")
	}
}

func TestGuidanceStorageCheckedBeforePromptsAllOnlineRoles(t *testing.T) {
	for _, role := range []string{"participant", "witness", "mirror", "auditor", "upload-station"} {
		t.Run(role, func(t *testing.T) {
			p := preparationFixture(t, role)
			err := p.initProfile()
			if err == nil || !strings.Contains(err.Error(), "ask your coordinator") || !strings.Contains(err.Error(), "3) Import") {
				t.Fatalf("missing actionable storage gate: %v", err)
			}
			if strings.Contains(p.ui.output.(*bytes.Buffer).String(), "Phase for this profile") {
				t.Fatal("prompted before prerequisites")
			}
		})
	}
}

func TestGuidanceCatalogExchangeOrder(t *testing.T) {
	for _, tc := range []struct{ role, stage, before, after string }{
		{"coordinator", "phase1-turns", "grant", "deliver-grant"},
		{"coordinator", "phase1-turns", "deliver-grant", "prepare-return-receipt"},
		{"coordinator", "operational-evidence", "evidence-receive", "collect-submissions"},
		{"coordinator", "operational-evidence", "collect-submissions", "ops-prepare"},
		{"auditor", "audit", "receive-audit-inputs", "audit"},
		{"auditor", "audit", "submit", "notify-submission"},
		{"witness", "phase1", "submit", "notify-submission"},
		{"mirror", "phase2", "submit", "notify-submission"},
		{"release-signer", "assignment", "receive-signing-inputs", "offline"},
		{"upload-station", "upload", "receive-release", "release-verify"},
		{"coordinator", "decision", "prepare-decision", "deliver-decision"},
		{"coordinator", "decision", "collect-decision-signatures", "verify-decision"},
		{"auditor", "decision", "sign-decision", "return-decision-signature"},
	} {
		positions := map[string]int{}
		for _, stage := range roleFlowStages(tc.role) {
			if stage.ID == tc.stage {
				for i, task := range stage.Tasks {
					positions[task.ID] = i + 1
				}
			}
		}
		if positions[tc.before] == 0 || positions[tc.after] <= positions[tc.before] {
			t.Errorf("%+v: %v", tc, positions)
		}
	}
}

func TestGuidancePrivateGrantDeliveryIsScopedAndSecretSafe(t *testing.T) {
	p := preparationFixture(t, "participant")
	prepareTestPublicStorage(t, p)
	f := flowFixture(t)
	f.state.Profile.Work = p.d.Work
	f.state.Role = "coordinator"
	f.stages = []flowStage{{ID: "phase1-turns"}}
	prefix, err := access.Prefix("sha256:"+strings.Repeat("1", 64), "participant", "alice")
	if err != nil {
		t.Fatal(err)
	}
	g := access.Grant{Schema: access.GrantSchema, Provider: "r2", CeremonyID: "sha256:" + strings.Repeat("1", 64), Role: "participant", IdentityID: "alice", Endpoint: "https://account.invalid", InboxBucket: "inbox", Prefix: prefix, IssuedAt: time.Now().UTC().Format(time.RFC3339), ExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339), MinimumRemaining: "10m", Credentials: access.SessionCredentials{AccessKeyID: "TEST_ID", SecretAccessKey: "TEST_SECRET_CANARY", SessionToken: "TEST_TOKEN_CANARY"}}
	path := filepath.Join(p.d.Work, "alice.grant.json")
	if err := writeJSONNoReplace(path, g, 0600); err != nil {
		t.Fatal(err)
	}
	command := []string{"relay", "coordinator", "grant", "--identity", "alice", "--role", "participant", "--storage", "/work/ceremony/config/relay-storage.json", "--out", "/work/alice.grant.json"}
	f.state.Attempts = []flowAttempt{{ID: "issued-1", Task: "grant", Stage: "phase1-turns", Status: "succeeded", Command: command}}
	task := flowTask{ID: "deliver-grant", Handoff: true}
	f.ui.input = bufio.NewReader(strings.NewReader("2\n"))
	if err := f.deliverPrivateGrant(task); err != nil {
		t.Fatal(err)
	}
	if f.grantDeliveryComplete(task) {
		t.Fatal("waiting counted as delivery")
	}
	f.ui.input = bufio.NewReader(strings.NewReader("1\n"))
	if err := f.deliverPrivateGrant(task); err != nil {
		t.Fatal(err)
	}
	if !f.grantDeliveryComplete(task) {
		t.Fatal("exact delivery not retained")
	}
	output := f.ui.output.(*bytes.Buffer).String()
	state, err := os.ReadFile(f.path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"TEST_SECRET_CANARY", "TEST_TOKEN_CANARY", "TEST_ID"} {
		if strings.Contains(output, secret) || bytes.Contains(state, []byte(secret)) {
			t.Fatal("private grant contents leaked")
		}
	}
	f.state.Attempts = append(f.state.Attempts, flowAttempt{ID: "issued-2", Task: "grant", Stage: "phase1-turns", Status: "succeeded", Command: command})
	if f.grantDeliveryComplete(task) {
		t.Fatal("new issuance inherited old delivery")
	}
	g.ExpiresAt = time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)
	if err := saveJSONAtomic(path, g); err != nil {
		t.Fatal(err)
	}
	if err := f.deliverPrivateGrant(task); err == nil {
		t.Fatal("expired grant delivered")
	}
}

func TestGuidanceAuditUploadUsesExactOutputsAndRejectsExtras(t *testing.T) {
	p := preparationFixture(t, "auditor")
	f := flowFixture(t)
	f.state.Profile.Work = p.d.Work
	f.state.Role = "auditor"
	f.stages = []flowStage{{ID: "audit"}}
	for _, name := range []string{"custom-report.json", "custom-signature.sig"} {
		if err := writePublicTextOnce(filepath.Join(p.d.Work, name), name); err != nil {
			t.Fatal(err)
		}
	}
	id := "flow-" + strings.Repeat("a", 32)
	f.state.Attempts = []flowAttempt{{ID: id, Task: "audit", Stage: "audit", Status: "succeeded", Command: []string{"mpc-ceremony", "audit", "--out", "/work/custom-report.json", "--audit-signature", "/work/custom-signature.sig"}}}
	task := submitFlow("auditor", "phase2")
	prepared, err := f.prepareAuditUpload(task)
	if err != nil {
		t.Fatal(err)
	}
	dir := ""
	for _, field := range prepared.Fields {
		if field.Flag == "dir" {
			dir = field.Default
		}
	}
	if dir != "/work/audit-upload-"+id {
		t.Fatalf("wrong directory: %s", dir)
	}
	if _, err := f.prepareAuditUpload(task); err != nil {
		t.Fatal("identical retry failed", err)
	}
	local := flowHostPath(f.state.Profile, dir)
	raw, err := os.ReadFile(filepath.Join(local, "audit.json"))
	if err != nil || string(raw) != "custom-report.json" {
		t.Fatal("wrong report copied")
	}
	if err := writePublicTextOnce(filepath.Join(local, "unexpected.txt"), "do not upload"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.prepareAuditUpload(task); err == nil {
		t.Fatal("additional files accepted")
	}
}
