package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	storagesetup "github.com/zksecurity/relay/scripts/storage-setup"
)

type awsSetupRunner func(context.Context, string, []string, io.Writer) ([]byte, error)

type awsSetupBuffer struct{ data bytes.Buffer }

func (b *awsSetupBuffer) Write(p []byte) (int, error) {
	if b.data.Len()+len(p) > 1024*1024 {
		return 0, errors.New("AWS output exceeded the allowed size")
	}
	return b.data.Write(p)
}

// Do not inherit credentials, alternate endpoints, shell startup hooks, or
// unattended provisioning acknowledgments. Explicit host profile files remain
// available; they are never mounted into a ceremony container.
func awsSetupEnvironment() []string {
	var env []string
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(key, "AWS_") && key != "AWS_CONFIG_FILE" && key != "AWS_SHARED_CREDENTIALS_FILE" && key != "AWS_LOGIN_CACHE_DIRECTORY" {
			continue
		}
		if key == "BASH_ENV" || key == "ENV" || strings.HasPrefix(key, "BASH_FUNC_") || key == "SHELLOPTS" || key == "BASHOPTS" {
			continue
		}
		env = append(env, entry)
	}
	return append(env, "AWS_PAGER=", "AWS_CLI_AUTO_PROMPT=off", "AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true")
}

func (w *coordinatorWizard) awsSetupCommand(binary string, args []string, progress io.Writer) ([]byte, error) {
	duration := time.Minute
	if binary == "bash" {
		duration = 45 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()
	go func() {
		select {
		case <-w.interrupted:
			cancel()
		case <-ctx.Done():
		}
	}()
	if w.awsSetupRun != nil {
		return w.awsSetupRun(ctx, binary, args, progress)
	}
	if _, err := exec.LookPath(binary); err != nil {
		return nil, fmt.Errorf("%s is not installed; see docs/maintainer/aws.md for AWS setup prerequisites", binary)
	}
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Env = awsSetupEnvironment()
	cmd.WaitDelay = time.Second
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	// Never echo AWS errors or credential-process output, which may contain
	// credentials. Provisioning progress comes only from the bundled script.
	var captured awsSetupBuffer
	cmd.Stdout = &captured
	if progress != nil {
		cmd.Stdout = progress
	}
	if err := cmd.Run(); err != nil {
		return nil, errors.New("AWS helper failed or timed out; check your selected login and permissions, then review retained resources before retrying")
	}
	return captured.data.Bytes(), nil
}

func (w *coordinatorWizard) setupAWS() error {
	if err := w.requirePreviousSessionClosed(); err != nil {
		return err
	}
	fmt.Fprintln(w.output, "Use an existing AWS CLI v2 login on this machine. No AWS password or ceremony signing key is requested. Provisioning also needs Bash and jq. If you have no login, follow docs/maintainer/aws.md; Relay will not create an AWS account or access key.")
	raw, err := w.awsSetupCommand("aws", []string{"configure", "list-profiles"}, nil)
	if err != nil {
		return err
	}
	var profiles []setupChoice
	for _, profile := range strings.Fields(string(raw)) {
		if regexp.MustCompile(`^[A-Za-z0-9_.-]+$`).MatchString(profile) {
			profiles = append(profiles, setupChoice{profile, profile})
		}
	}
	if len(profiles) == 0 {
		return errors.New("no supported AWS profiles found; configure an AWS CLI login first (see docs/maintainer/aws.md)")
	}
	profile, err := w.choose("Choose your AWS login", "", profiles)
	if err != nil {
		return err
	}
	regionRaw, _ := w.awsSetupCommand("aws", []string{"--profile", profile, "configure", "get", "region"}, nil)
	loginRegion := strings.TrimSpace(string(regionRaw))
	promptedRegion := loginRegion == ""
	if promptedRegion {
		loginRegion, err = w.required("AWS region for this login", "")
		if err != nil {
			return err
		}
	}
	if !regexp.MustCompile(`^[a-z]{2}(-[a-z0-9]+)+-[0-9]+$`).MatchString(loginRegion) {
		return errors.New("invalid AWS region")
	}
	raw, err = w.awsSetupCommand("aws", []string{"--profile", profile, "--region", loginRegion, "sts", "get-caller-identity", "--output", "json"}, nil)
	if err != nil {
		return err
	}
	var identity awsLoginIdentity
	if json.Unmarshal(raw, &identity) != nil || !regexp.MustCompile(`^[0-9]{12}$`).MatchString(identity.Account) || !regexp.MustCompile(`^arn:aws:(iam|sts)::[0-9]{12}:(user|role|assumed-role)/[A-Za-z0-9+=,.@_/-]+$`).MatchString(identity.Arn) || !strings.Contains(identity.Arn, "::"+identity.Account+":") {
		return errors.New("expected an AWS IAM user or role; root credentials are not supported")
	}
	fmt.Fprintf(w.output, "AWS account: %s\nIdentity: %s\n", identity.Account, identity.Arn)
	if err := w.confirm("Confirm this is the intended ceremony account, not an unrelated company account", "USE ACCOUNT"); err != nil {
		return err
	}
	method, err := w.choose("Amazon S3 storage", "", []setupChoice{{"existing", "Use existing ceremony resources (no infrastructure changes)"}, {"create", "Create or repair dedicated ceremony resources (AWS charges apply)"}})
	if err != nil {
		return err
	}
	region := loginRegion
	if !promptedRegion {
		region, err = w.required("AWS region", loginRegion)
		if err != nil {
			return err
		}
	}
	if !regexp.MustCompile(`^[a-z]{2}(-[a-z0-9]+)+-[0-9]+$`).MatchString(region) {
		return errors.New("invalid AWS region")
	}
	v := map[string]string{"provider": "aws", "profile": "relay-coordinator", "issuer-profile": "relay-coordinator", "region": region}
	if method == "existing" {
		for _, field := range []struct{ key, label string }{
			{"published-bucket", "Published transcript bucket name"},
			{"inbox-bucket", "Private submissions bucket name"},
			{"published-base-url", "Public HTTPS transcript address (for example your CloudFront URL)"},
			{"grant-role-arn", "Upload-grant IAM role ARN"},
		} {
			v[field.key], err = w.required(field.label, w.d.Storage[field.key])
			if err != nil {
				return err
			}
		}
		grantDefault := "1h"
		if strings.HasPrefix(identity.Arn, "arn:aws:iam::"+identity.Account+":user/") {
			grantDefault = "12h"
		}
		v["grant-role-max-ttl"], err = w.required("Grant role maximum session duration (1h–12h; assumed-role logins are limited to 1h)", grantDefault)
		if err != nil {
			return err
		}
	} else {
		v, err = w.provisionAWS(profile, region, identity.Account, identity.Arn)
		if err != nil {
			return err
		}
		v["profile"], v["issuer-profile"] = "relay-coordinator", "relay-coordinator"
	}
	settings := coordinatorStorageSettings{"relay-coordinator-storage-settings-v1", v}
	if _, err := settings.infrastructure(); err != nil {
		return err
	}
	if !strings.HasPrefix(v["grant-role-arn"], "arn:aws:iam::"+identity.Account+":role/") {
		return errors.New("the grant role must belong to the selected AWS account")
	}
	if strings.Contains(identity.Arn, ":assumed-role/") && v["grant-role-max-ttl"] != "1h" {
		return errors.New("this assumed-role login requires a 1h grant maximum")
	}
	fmt.Fprintf(w.output, "Public transcript: %s\nPublished bucket: %s\nPrivate inbox: %s\n", v["published-base-url"], v["published-bucket"], v["inbox-bucket"])
	raw, err = w.awsSetupCommand("aws", []string{"configure", "export-credentials", "--profile", profile, "--region", region, "--format", "process"}, nil)
	if err != nil {
		return err
	}
	exported, err := parseAWSProcess(raw, time.Now(), awsLoginReserve)
	if err != nil {
		return err
	}
	var credentials string
	if exported.Expiration != "" {
		binding, err := newAWSLoginBinding(profile, region, identity)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			select {
			case <-w.interrupted:
				cancel()
			case <-ctx.Done():
			}
		}()
		_, err = refreshAWSLogin(ctx, binding)
		cancel()
		if err != nil {
			return err
		}
		fmt.Fprintf(w.output, "Renewable AWS login: %s\nAWS CLI: %s\nHost config: %s\nHost credential source: %s\nHost login cache: %s\n", profile, binding.Binary, binding.Config, binding.Credentials, binding.Cache)
		fmt.Fprintln(w.output, "Relay will renew temporary credentials on this coordinator while an action runs. Only verified temporary credentials enter Docker; the login cache stays on this host. Renewal ends when the overall login session expires. Log in again on this host when requested. Updating the AWS CLI requires repeating this setup. Use a dedicated, least-privilege ceremony login.")
		encoded, err := json.Marshal(binding)
		if err != nil {
			return err
		}
		credentials = string(encoded)
	} else {
		if exported.SessionToken != "" || !strings.HasPrefix(identity.Arn, "arn:aws:iam::"+identity.Account+":user/") {
			return errors.New("non-expiring AWS credentials must belong to an IAM user")
		}
		binding, bindErr := newAWSLoginBinding(profile, region, identity)
		if bindErr != nil {
			return bindErr
		}
		binding.Schema = awsLoginSchemaV2
		binding.StaticIssuer = true
		sessionRaw, sessionErr := w.awsSetupCommand("aws", []string{"--profile", profile, "--region", region, "sts", "get-session-token", "--duration-seconds", "43200", "--output", "json"}, nil)
		if sessionErr != nil {
			return errors.New("IAM-user login could not obtain a 12-hour temporary coordinator session; check sts:GetSessionToken permission")
		}
		if _, sessionErr = parseAWSGetSessionToken(sessionRaw, time.Now()); sessionErr != nil {
			return sessionErr
		}
		encoded, marshalErr := json.Marshal(binding)
		if marshalErr != nil {
			return marshalErr
		}
		credentials = string(encoded)
		fmt.Fprintf(w.output, "Renewable 12-hour AWS coordinator sessions and direct scoped grant issuance will use IAM user profile %s on this host. The access key is not copied into Relay settings or Docker.\n", profile)
	}
	if err := w.confirm("Save these settings and the displayed credential configuration", "SAVE SETTINGS"); err != nil {
		return err
	}
	root := w.credentialRoot
	if root == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			return err
		}
		root = filepath.Join(base, "relay", "storage-credentials")
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return err
	}
	if err := validateRoleMount(root, false); err != nil {
		return err
	}
	dir, err := os.MkdirTemp(root, "aws-")
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			if err := os.RemoveAll(dir); err != nil {
				fmt.Fprintln(w.output, "Could not remove staged credentials; inspect the protected credential folder.")
			}
		}
	}()
	path := filepath.Join(dir, "aws")
	if err := os.WriteFile(path, []byte(credentials), 0600); err != nil {
		return errors.New("could not save protected AWS credentials")
	}
	old := w.d
	w.d.Storage, w.d.Credentials = v, path
	w.d.R2Parent, w.d.R2Control, w.d.SessionCredentials = "", "", false
	if err := w.save(); err != nil {
		w.d = old
		return err
	}
	committed = true
	fmt.Fprintln(w.output, "Settings saved. Next: Check storage to verify current access and public/private delivery. Resource setup alone does not prove these checks passed.")
	return nil
}

func parseAWSGetSessionToken(raw []byte, now time.Time) (awsProcessCredentials, error) {
	var session struct {
		Credentials struct {
			AccessKeyID     string `json:"AccessKeyId"`
			SecretAccessKey string `json:"SecretAccessKey"`
			SessionToken    string `json:"SessionToken"`
			Expiration      string `json:"Expiration"`
		} `json:"Credentials"`
	}
	if len(raw) > 64*1024 || json.Unmarshal(raw, &session) != nil {
		return awsProcessCredentials{}, errAWSLoginInvalid
	}
	c := awsProcessCredentials{Version: 1, AccessKeyId: session.Credentials.AccessKeyID, SecretAccessKey: session.Credentials.SecretAccessKey, SessionToken: session.Credentials.SessionToken, Expiration: session.Credentials.Expiration}
	return parseAWSProcess(mustJSON(c), now, awsLoginReserve)
}

func awsSnapshot(raw []byte) (string, string, error) {
	var c struct {
		Version                                                int
		AccessKeyId, SecretAccessKey, SessionToken, Expiration string
	}
	if len(raw) > 64*1024 || json.Unmarshal(raw, &c) != nil || c.Version != 1 {
		return "", "", errors.New("invalid AWS credential export; nothing saved")
	}
	valid := regexp.MustCompile(`^[A-Za-z0-9/+=]+$`)
	if !valid.MatchString(c.AccessKeyId) || !valid.MatchString(c.SecretAccessKey) || (c.SessionToken != "" && !valid.MatchString(c.SessionToken)) {
		return "", "", errors.New("invalid AWS credential fields; nothing saved")
	}
	expiry := "no expiry supplied (protect and rotate this credential)"
	if c.Expiration != "" {
		t, err := time.Parse(time.RFC3339, c.Expiration)
		if err != nil || time.Until(t) < 15*time.Minute {
			return "", "", errors.New("AWS credentials expire in under 15 minutes or have an invalid expiry; refresh your login")
		}
		expiry = t.UTC().Format(time.RFC3339)
	} else if c.SessionToken != "" {
		return "", "", errors.New("temporary AWS credentials have no expiry; cannot safely save this snapshot")
	}
	text := "[relay-coordinator]\naws_access_key_id = " + c.AccessKeyId + "\naws_secret_access_key = " + c.SecretAccessKey + "\n"
	if c.SessionToken != "" {
		text += "aws_session_token = " + c.SessionToken + "\n"
	}
	return text, expiry, nil
}

func (w *coordinatorWizard) provisionAWS(profile, region, account, arn string) (map[string]string, error) {
	if w.awsSetupRun == nil {
		for _, binary := range []string{"bash", "jq", "grep", "realpath", "stat"} {
			if _, err := exec.LookPath(binary); err != nil {
				return nil, fmt.Errorf("%s is required for AWS provisioning; see docs/maintainer/aws.md", binary)
			}
		}
	}
	prefix, err := w.required("Dedicated resource prefix (3–32 lowercase letters, numbers or hyphens)", "relay-ceremony")
	if err != nil {
		return nil, err
	}
	if !regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$`).MatchString(prefix) {
		return nil, errors.New("invalid resource prefix")
	}
	// All interpolated values are validated above; no operator-authored shell
	// or downloaded scripts are executed.
	grantTTL := "1h"
	if strings.HasPrefix(arn, "arn:aws:iam::"+account+":user/") {
		grantTTL = "12h"
	}
	fmt.Fprintf(w.output, "AWS account: %s; region: %s\nPublished bucket: %s-%s-published\nPrivate inbox: %s-%s-inbox\nGrant role: %s-inbox-grant (%s maximum)\n", account, region, prefix, account, prefix, account, prefix, grantTTL)
	fmt.Fprintln(w.output, "This creates or repairs S3 buckets, CloudFront delivery and IAM policies. Existing resources with these names have their policies/settings reapplied; use only dedicated ceremony resources. AWS charges apply. Partial resources remain after failures; there is no automatic retry or rollback. CloudFront may take several minutes. A 1h grant cap also applies to assumed-role logins.")
	if err := w.confirm("Approve these specific cloud resource changes", "CREATE RESOURCES"); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp("", "relay-aws-setup-")
	if err != nil {
		return nil, err
	}
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(w.output, "Non-secret setup files retained at: %s\n", dir)
	for _, name := range []string{"setup-aws.sh", "coordinator-settings.sh"} {
		raw, err := storagesetup.AWS.ReadFile(name)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
			return nil, err
		}
	}
	config := fmt.Sprintf("AWS_PROFILE='%s'\nAWS_REGION='%s'\nRESOURCE_PREFIX='%s'\nPUBLISHED_BUCKET=''\nINBOX_BUCKET=''\nGRANT_ROLE_NAME=''\nGRANT_ROLE_MAX_TTL='%s'\nUSE_EXISTING_GRANT_ROLE='no'\nEXPECTED_ACCOUNT='%s'\nEXPECTED_CALLER_ARN='%s'\nCONFIRM_CREATE='yes'\n", profile, region, prefix, grantTTL, account, arn)
	configPath := filepath.Join(dir, "approved.env")
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		return nil, err
	}
	out := filepath.Join(dir, "settings.json")
	if _, err := w.awsSetupCommand("bash", []string{filepath.Join(dir, "setup-aws.sh"), "--coordinator-settings", out, configPath}, w.output); err != nil {
		return nil, err
	}
	var settings coordinatorStorageSettings
	if err := setupReadJSON(out, &settings); err != nil {
		return nil, err
	}
	if _, err := settings.infrastructure(); err != nil {
		return nil, err
	}
	return settings.Settings, nil
}
