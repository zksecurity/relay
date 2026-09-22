package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

func syntheticAWSLease(expiry time.Time) awsProcessCredentials {
	return awsProcessCredentials{Version: 1, AccessKeyId: "TESTACCESS", SecretAccessKey: "syntheticSecret", SessionToken: "syntheticToken", Expiration: expiry.Format(time.RFC3339)}
}
func TestAWSLoginCredentialValidation(t *testing.T) {
	now := time.Now()
	c := syntheticAWSLease(now.Add(14 * time.Minute))
	raw, _ := json.Marshal(c)
	if _, err := parseAWSProcess(raw, now, awsLoginReserve); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		strings.Replace(string(raw), `"Version":1`, `"Version":1,"Version":1`, 1),
		string(raw) + ` {}`, strings.Replace(string(raw), `"Version":1`, `"Version":2`, 1),
		strings.Replace(string(raw), `"syntheticToken"`, `"bad\nvalue"`, 1),
		`{"Version":1,"AccessKeyId":"TEST","SecretAccessKey":"secret","SessionToken":"token"}`,
	} {
		if _, err := parseAWSProcess([]byte(raw), now, awsLoginReserve); err == nil {
			t.Fatal("accepted malformed credentials")
		}
	}
	if _, err := parseAWSProcess(raw, now.Add(12*time.Minute), awsLoginReserve); err == nil {
		t.Fatal("accepted expiring lease")
	}
}
func TestAWSLoginStablePrincipal(t *testing.T) {
	a := awsLoginIdentity{"123456789012", "arn:aws:sts::123456789012:assumed-role/ceremony/session1", "AROATEST:session1"}
	b := a
	b.Arn = strings.Replace(a.Arn, "session1", "session2", 1)
	b.UserId = "AROATEST:session2"
	x, err := normalizedAWSIdentity(a)
	if err != nil {
		t.Fatal(err)
	}
	y, err := normalizedAWSIdentity(b)
	if err != nil || x != y {
		t.Fatal("session renewal changed stable identity")
	}
	b.UserId = "AROAOTHER:session2"
	y, _ = normalizedAWSIdentity(b)
	if x == y {
		t.Fatal("principal replacement ignored")
	}
}
func TestAWSLoginEnvironmentIsolated(t *testing.T) {
	t.Setenv("AWS_PROFILE", "unrelated")
	t.Setenv("AWS_ENDPOINT_URL", "http://wrong")
	t.Setenv("AWS_ACCESS_KEY_ID", "wrong")
	b := awsLoginBinding{Config: "/host/config", Credentials: "/host/credentials", Cache: "/host/cache", Region: "us-east-1"}
	c := syntheticAWSLease(time.Now().Add(time.Hour))
	env := strings.Join(awsLoginEnvironment(b, &c), "\n")
	if strings.Contains(env, "wrong") || strings.Contains(env, "/host/") {
		t.Fatal("identity check inherited another provider")
	}
	if !strings.Contains(env, "AWS_ACCESS_KEY_ID=TESTACCESS") {
		t.Fatal("captured credentials missing")
	}
	source := strings.Join(awsLoginEnvironment(b, nil), "\n")
	if !strings.Contains(source, "AWS_LOGIN_CACHE_DIRECTORY=/host/cache") {
		t.Fatal("cache binding missing")
	}
}
func TestAWSLoginRenewalRetriesAndRotates(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "current.json")
		c := syntheticAWSLease(time.Now().Add(15 * time.Minute))
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		calls := 0
		refresh := func(context.Context, awsLoginBinding) (awsProcessCredentials, error) {
			calls++
			if calls == 1 {
				return c, errors.New("temporary outage")
			}
			next := syntheticAWSLease(time.Now().Add(15 * time.Minute))
			next.AccessKeyId = "ROTATED"
			return next, nil
		}
		done := make(chan error, 1)
		go func() { done <- maintainAWSLogin(ctx, awsLoginBinding{}, path, c, refresh) }()
		time.Sleep(71 * time.Second)
		synctest.Wait()
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if calls != 2 || !strings.Contains(string(raw), "ROTATED") {
			t.Fatal("did not recover and rotate")
		}
		cancel()
		if !errors.Is(<-done, context.Canceled) {
			t.Fatal("cancellation not propagated")
		}
	})
}
func TestAWSLoginRenewalStopsBeforeExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		start := time.Now()
		c := syntheticAWSLease(start.Add(5 * time.Minute))
		err := maintainAWSLogin(context.Background(), awsLoginBinding{}, filepath.Join(t.TempDir(), "current.json"), c, func(context.Context, awsLoginBinding) (awsProcessCredentials, error) { return c, errors.New("offline") })
		if err == nil || time.Since(start) >= 2*time.Minute {
			t.Fatal("renewal crossed safety reserve", err, time.Since(start))
		}
	})
}
func TestAWSLoginRenewalRejectsDriftImmediately(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		start := time.Now()
		c := syntheticAWSLease(start.Add(time.Hour))
		err := maintainAWSLogin(context.Background(), awsLoginBinding{}, filepath.Join(t.TempDir(), "current.json"), c, func(context.Context, awsLoginBinding) (awsProcessCredentials, error) { return c, errAWSLoginInvalid })
		if !errors.Is(err, errAWSLoginInvalid) || time.Since(start) != time.Minute {
			t.Fatal("drift was retried", err)
		}
	})
}
func TestAWSLoginAtomicConcurrentReads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "current.json")
	c := syntheticAWSLease(time.Now().Add(time.Hour))
	if err := saveJSONAtomic(path, c); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 100 {
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Error(err)
					return
				}
				if _, err := parseAWSProcess(raw, time.Now(), time.Second); err != nil {
					t.Error(err)
					return
				}
			}
		})
	}
	for range 30 {
		if err := saveJSONAtomic(path, c); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
}

func fakeAWSLogin(t *testing.T) awsLoginBinding {
	t.Helper()
	dir := t.TempDir()
	identity := awsLoginIdentity{"123456789012", "arn:aws:iam::123456789012:user/ceremony", "AIDATEST"}
	lease := syntheticAWSLease(time.Now().Add(15 * time.Minute))
	raw, _ := json.Marshal(lease)
	id, _ := json.Marshal(identity)
	script := "#!/bin/sh\ncase \"$1\" in\nconfigure) printf '%s' '" + string(raw) + "';;\nsts) test \"$AWS_ACCESS_KEY_ID\" = TESTACCESS || exit 2; test \"$AWS_CONFIG_FILE\" = /nonexistent || exit 3; printf '%s' '" + string(id) + "';;\n*) exit 4;;\nesac\n"
	path := filepath.Join(dir, "aws")
	if err := os.WriteFile(path, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	digest, err := awsBinaryDigest(path)
	if err != nil {
		t.Fatal(err)
	}
	return awsLoginBinding{Schema: awsLoginSchema, Binary: path, SHA256: digest, Profile: "test", Region: "us-east-1", Config: filepath.Join(dir, "config"), Credentials: filepath.Join(dir, "credentials"), Cache: filepath.Join(dir, "cache"), Identity: identity}
}
func TestAWSLoginRefreshBindsExportedIdentity(t *testing.T) {
	b := fakeAWSLogin(t)
	if _, err := refreshAWSLogin(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	b.Identity.UserId = "AIDAOTHER"
	if _, err := refreshAWSLogin(context.Background(), b); !errors.Is(err, errAWSLoginInvalid) {
		t.Fatal("identity replacement accepted", err)
	}
	b = fakeAWSLogin(t)
	if err := os.WriteFile(b.Binary, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := refreshAWSLogin(context.Background(), b); err == nil {
		t.Fatal("changed executable accepted")
	}
}

func TestAWSIAMUserBindingCreatesTwelveHourTemporarySession(t *testing.T) {
	b := fakeAWSLogin(t)
	b.Schema, b.StaticIssuer = awsLoginSchemaV2, true
	identity, _ := json.Marshal(b.Identity)
	expires := time.Now().Add(12 * time.Hour).UTC().Format(time.RFC3339)
	script := `#!/bin/sh
if test "$1" = configure; then
 printf '%s' '{"Version":1,"AccessKeyId":"STATICACCESS","SecretAccessKey":"STATICSECRET"}'
elif test "$5" = sts; then
 printf '%s' '{"Credentials":{"AccessKeyId":"TEMPACCESS","SecretAccessKey":"TEMPSECRET","SessionToken":"TEMPTOKEN","Expiration":"` + expires + `"}}'
elif test "$1" = sts; then
 test "$AWS_ACCESS_KEY_ID" = TEMPACCESS || exit 2
 test "$AWS_CONFIG_FILE" = /nonexistent || exit 3
 printf '%s' '` + string(identity) + `'
else
 exit 4
fi
`
	if err := os.WriteFile(b.Binary, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	var err error
	b.SHA256, err = awsBinaryDigest(b.Binary)
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := refreshAWSLogin(context.Background(), b)
	if err != nil {
		t.Fatal(err)
	}
	if credentials.AccessKeyId != "TEMPACCESS" || credentials.SessionToken != "TEMPTOKEN" || credentials.Expiration != expires {
		t.Fatalf("unexpected temporary session: %#v", credentials)
	}
}

func TestAWSIAMUserSessionRenewsNearExpiry(t *testing.T) {
	now := time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC)
	b := awsLoginBinding{Schema: awsLoginSchemaV2, StaticIssuer: true}
	c := syntheticAWSLease(now.Add(12 * time.Hour))
	delay, expiry := awsLoginRenewalDelay(b, c, now)
	want := 12*time.Hour - awsStaticLoginRenewalLead
	if delay != want || !expiry.Equal(now.Add(12*time.Hour)) {
		t.Fatalf("renewal delay = %s, expiry = %s; want %s", delay, expiry, want)
	}
	b.Schema, b.StaticIssuer = awsLoginSchema, false
	if delay, _ := awsLoginRenewalDelay(b, c, now); delay != time.Minute {
		t.Fatalf("legacy refresh delay = %s", delay)
	}
}

func TestAWSIAMUserRenewalRetriesBeforeSafetyDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		start := time.Now()
		c := syntheticAWSLease(start.Add(12 * time.Hour))
		b := awsLoginBinding{Schema: awsLoginSchemaV2, StaticIssuer: true}
		ctx, cancel := context.WithCancel(context.Background())
		calls := 0
		done := make(chan error, 1)
		go func() {
			done <- maintainAWSLogin(ctx, b, filepath.Join(t.TempDir(), "current.json"), c, func(context.Context, awsLoginBinding) (awsProcessCredentials, error) {
				calls++
				if calls == 1 {
					return c, errors.New("temporary outage")
				}
				next := syntheticAWSLease(time.Now().Add(12 * time.Hour))
				next.AccessKeyId = "ROTATED"
				return next, nil
			})
		}()
		time.Sleep(12*time.Hour - awsStaticLoginRenewalLead + 11*time.Second)
		synctest.Wait()
		if calls != 2 {
			t.Fatalf("refresh calls = %d", calls)
		}
		cancel()
		if !errors.Is(<-done, context.Canceled) {
			t.Fatal("cancellation not propagated")
		}
	})
}
func TestAWSLoginBindingNeverMounted(t *testing.T) {
	b := fakeAWSLogin(t)
	path := filepath.Join(t.TempDir(), "binding")
	if err := saveJSONAtomic(path, b); err != nil {
		t.Fatal(err)
	}
	o := dockerRoleOptions{role: "coordinator", image: "sha256:" + strings.Repeat("a", 64), platform: "linux/amd64", work: t.TempDir(), credentials: path}
	_ = os.Chmod(o.work, 0700)
	for _, command := range [][]string{{"aws", "sts", "get-caller-identity"}, {"mpc-ceremony", "version"}} {
		args, err := dockerRoleArgs(o, command, 501, 20)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(strings.Join(args, " "), path) {
			t.Fatal("host binding mounted")
		}
	}
	o.awsLoginRuntime = t.TempDir()
	o.credentials = ""
	_ = os.Chmod(o.awsLoginRuntime, 0700)
	args, err := dockerRoleArgs(o, []string{"aws", "sts", "get-caller-identity"}, 501, 20)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "dst=/credentials/aws-login,readonly") || !strings.Contains(joined, "AWS_CONFIG_FILE=/credentials/aws-login/config") {
		t.Fatal("missing renewable provider mount")
	}
	if _, err := dockerRoleArgs(o, []string{"mpc-ceremony", "version"}, 501, 20); err == nil {
		t.Fatal("proof received renewable credentials")
	}
}

func TestAWSLoginProviderCompatibility(t *testing.T) {
	for _, test := range []struct {
		binding, provider string
		want              bool
	}{
		{awsLoginSchema, awsLoginSchema, true},
		{awsLoginSchema, awsLoginSchemaV2, true},
		{awsLoginSchemaV2, awsLoginSchema, false},
		{awsLoginSchemaV2, awsLoginSchemaV2, true},
	} {
		if got := compatibleAWSLoginProvider(test.binding, test.provider); got != test.want {
			t.Fatalf("compatibility %s/%s = %v", test.binding, test.provider, got)
		}
	}
}
func TestAWSLoginDockerCleanup(t *testing.T) {
	for _, scenario := range []string{"completion", "cancellation", "creation-cancellation"} {
		t.Run(scenario, func(t *testing.T) {
			cancelAction := scenario != "completion"
			b := fakeAWSLogin(t)
			dir := t.TempDir()
			t.Setenv("RELAY_AWS_FAKE_DOCKER", dir)
			script := `#!/bin/sh
shift 2
case "$1" in
run) printf 'relay-aws-login-v1\n';;
create)
 shift
 while test "$#" -gt 0; do
  if test "$1" = --name; then printf '%s' "$2" > "$RELAY_AWS_FAKE_DOCKER/owner"; fi
  shift
 done
 if test -f "$RELAY_AWS_FAKE_DOCKER/create-wait"; then exec sleep 30; fi
 printf '%064d\n' 1;;
start)
 touch "$RELAY_AWS_FAKE_DOCKER/started"
 if test -f "$RELAY_AWS_FAKE_DOCKER/wait"; then exec sleep 30; fi;;
inspect) printf '%064d ' 1; cat "$RELAY_AWS_FAKE_DOCKER/owner";;
stop) :;;
rm) rm "$RELAY_AWS_FAKE_DOCKER/owner"; touch "$RELAY_AWS_FAKE_DOCKER/removed";;
ps) test ! -f "$RELAY_AWS_FAKE_DOCKER/owner";;
*) exit 2;;
esac
`
			docker := filepath.Join(dir, "docker")
			_ = os.WriteFile(docker, []byte(script), 0700)
			if cancelAction {
				filename := "wait"
				if scenario == "creation-cancellation" {
					filename = "create-wait"
				}
				_ = os.WriteFile(filepath.Join(dir, filename), nil, 0600)
			}
			work := t.TempDir()
			_ = os.Chmod(work, 0700)
			o := dockerRoleOptions{role: "coordinator", image: "sha256:" + strings.Repeat("a", 64), platform: "linux/amd64", work: work}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				done <- runAWSLoginDockerContext(ctx, o, []string{"aws", "sts", "get-caller-identity"}, b, docker, "unix:///fake.sock")
			}()
			if cancelAction {
				deadline := time.Now().Add(5 * time.Second)
				for {
					marker := "started"
					if scenario == "creation-cancellation" {
						marker = "owner"
					}
					if _, err := os.Stat(filepath.Join(dir, marker)); err == nil {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("action did not start")
					}
					time.Sleep(10 * time.Millisecond)
				}
				cancel()
			}
			select {
			case err := <-done:
				if !cancelAction && err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("action failed to stop")
			}
			if _, err := os.Stat(filepath.Join(dir, "removed")); err != nil {
				t.Fatal("container not removed", err)
			}
		})
	}
}

func TestAWSGuidedTemporaryLoginSavesBinding(t *testing.T) {
	b := fakeAWSLogin(t)
	t.Setenv("PATH", filepath.Dir(b.Binary)+string(os.PathListSeparator)+os.Getenv("PATH"))
	w := awsSetupFixture(t, "1\nUSE ACCOUNT\n1\n\npublic-fixture\nprivate-fixture\nhttps://ceremony.example\narn:aws:iam::123456789012:role/grants\n\nSAVE SETTINGS\n")
	original := w.awsSetupRun
	w.awsSetupRun = func(ctx context.Context, binary string, args []string, progress io.Writer) ([]byte, error) {
		joined := strings.Join(args, " ")
		if strings.Contains(joined, "get-caller-identity") {
			return json.Marshal(b.Identity)
		}
		if strings.Contains(joined, "export-credentials") {
			return json.Marshal(syntheticAWSLease(time.Now().Add(14 * time.Minute)))
		}
		return original(ctx, binary, args, progress)
	}
	if err := w.setupAWS(); err != nil {
		t.Fatal(err)
	}
	binding, err := readAWSLoginBinding(w.d.Credentials)
	if err != nil || binding == nil {
		t.Fatal("renewable binding not saved", err)
	}
	raw, _ := os.ReadFile(w.d.Credentials)
	draft, _ := os.ReadFile(w.draftPath)
	for _, value := range []string{string(raw), string(draft), w.output.(*bytes.Buffer).String()} {
		if strings.Contains(value, "syntheticSecret") || strings.Contains(value, "syntheticToken") {
			t.Fatal("snapshot secret persisted or printed")
		}
	}
}

func TestAWSGuidedLoginWithoutSavedRegion(t *testing.T) {
	w := awsSetupFixture(t, "1\nus-east-1\nUSE ACCOUNT\n1\npublic-fixture\nprivate-fixture\nhttps://ceremony.example\narn:aws:iam::123456789012:role/grants\n\nSAVE SETTINGS\n")
	original := w.awsSetupRun
	w.awsSetupRun = func(ctx context.Context, binary string, args []string, progress io.Writer) ([]byte, error) {
		if strings.Join(args, " ") == "--profile test-account configure get region" {
			return nil, errors.New("not configured")
		}
		return original(ctx, binary, args, progress)
	}
	if err := w.setupAWS(); err != nil {
		t.Fatal(err)
	}
}
