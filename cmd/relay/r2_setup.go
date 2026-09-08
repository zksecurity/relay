package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func (w *coordinatorWizard) secret(label string) (string, error) {
	if w.readSecret != nil {
		return w.readSecret(label)
	}
	if w.input.Buffered() != 0 {
		return "", errors.New("do not paste multiple answers at once; enter credentials only at the hidden prompt")
	}
	return promptProtectedSecret(w.output, label)
}

func (w *coordinatorWizard) credential(label string) (string, error) {
	choice, err := w.choose(label, "", []setupChoice{{"paste", "Paste from my password manager or saved copy (hidden)"}, {"file", "Read an existing protected credential file"}, {"instructions", "Show how to obtain this credential"}, {"cancel", "Cancel"}})
	if err != nil {
		return "", err
	}
	switch choice {
	case "paste":
		return w.secret(label)
	case "file":
		path, err := w.required("Absolute path to the protected file (not the credential itself)", "")
		if err != nil {
			return "", err
		}
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return "", errors.New("use an absolute clean file path")
		}
		return readProtectedCredential(path)
	case "instructions":
		fmt.Fprintln(w.output, "Cloudflare dashboard → R2 object storage → Manage R2 API Tokens. Coordinator object credentials need Object Read & Write on the published and inbox buckets. The inbox parent must be a separate Object Read & Write credential restricted to the inbox bucket. Privacy checking needs a separate control-plane token with permission to read the selected bucket's domain configuration, or your authorized Wrangler login. Never paste a Cloudflare password or ceremony signing key.")
		fmt.Fprintln(w.output, "Guide: https://developers.cloudflare.com/r2/api/tokens/")
		return "", errors.New("return after obtaining the requested credential; nothing saved")
	default:
		return "", errors.New("cancelled; no credentials saved")
	}
}

func validR2Hex(value string, size int) bool {
	b, err := hex.DecodeString(value)
	return err == nil && len(b) == size && strings.ToLower(value) == value
}

// A new generation is staged outside work/trust/keys. It never replaces an
// existing credential file, and the draft changes only after every input passes.
func (w *coordinatorWizard) setupR2() (result error) {
	if err := w.requirePreviousSessionClosed(); err != nil {
		return err
	}
	fmt.Fprintln(w.output, "Set up existing Cloudflare R2 storage. No buckets, policies, tokens or objects are created by this step. You choose when to run live storage checks.")
	v := map[string]string{"provider": "r2", "region": "auto", "profile": "relay-coordinator"}
	method, err := w.choose("Select existing R2 storage", "", []setupChoice{{"login", "Find accounts and buckets using my authorized Wrangler login"}, {"manual", "Enter the account and bucket details manually"}})
	if err != nil {
		return err
	}
	control := ""
	if method == "login" {
		found, token, err := w.discoverR2()
		if err != nil {
			return err
		}
		for key, value := range found {
			v[key] = value
		}
		control = token
	}
	for _, field := range []struct{ key, label string }{{"account-id", "Cloudflare account ID"}, {"published-bucket", "Bucket for the public ceremony transcript"}, {"inbox-bucket", "Private bucket for role submissions"}, {"published-base-url", "Public HTTPS address of the transcript bucket"}} {
		if v[field.key] != "" {
			continue
		}
		value, err := w.required(field.label, w.d.Storage[field.key])
		if err != nil {
			return err
		}
		v[field.key] = value
	}
	if !validR2Hex(v["account-id"], 16) {
		return errors.New("Cloudflare account ID must be 32 lowercase hexadecimal characters")
	}
	v["endpoint"] = "https://" + v["account-id"] + ".r2.cloudflarestorage.com"
	mode, err := w.choose("Where should Relay keep the credentials?", "", []setupChoice{{"saved", "Save in protected local files"}, {"session", "Use for this session only (temporary disk files)"}, {"cancel", "Cancel"}})
	if err != nil {
		return err
	}
	if mode == "cancel" {
		return errors.New("cancelled; nothing saved")
	}
	fmt.Fprintln(w.output, "These credentials are not ceremony signing keys. Session-only also needs protected temporary files for Docker: normal exit removes them, but a crash, forced kill, backups or snapshots may retain them. This is not secure erasure or RAM-only storage.")
	access, secret, err := w.coordinatorR2Credential()
	if err != nil {
		return err
	}
	parentID, err := w.credential("Inbox-only parent Access Key ID")
	if err != nil {
		return err
	}
	parentSecret, err := w.credential("Inbox-only parent Secret Access Key")
	if err != nil {
		return err
	}
	if !validR2Hex(access, 16) || !validR2Hex(parentID, 16) || !validR2Hex(secret, 32) || !validR2Hex(parentSecret, 32) {
		return errors.New("R2 access key IDs must have 32 hexadecimal characters and secret access keys 64; no credentials saved")
	}
	if access == parentID {
		return errors.New("use a separate inbox-only parent credential, not the coordinator credential")
	}
	v["parent-access-key-id"] = parentID
	if control == "" {
		control, err = w.credential("R2 control-plane token for checking inbox privacy")
		if err != nil {
			return err
		}
	}
	if strings.TrimSpace(control) == "" || strings.ContainsAny(control, "\r\n\x00\t ") {
		return errors.New("invalid control credential; nothing saved")
	}
	s := coordinatorStorageSettings{"relay-coordinator-storage-settings-v1", v}
	if _, err := s.infrastructure(); err != nil {
		return err
	}
	fmt.Fprintf(w.output, "Account: %s\nPublic transcript: %s\nPublished bucket: %s\nPrivate inbox: %s\nCredential contents are hidden. Selected buckets and credential permissions have NOT yet been checked.\n", v["account-id"], v["published-base-url"], v["published-bucket"], v["inbox-bucket"])
	if err := w.confirm("Use these settings and stage the credentials in protected files", "SAVE SETTINGS"); err != nil {
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
		return errors.New("cannot create protected credential directory")
	}
	if err := validateRoleMount(root, false); err != nil {
		return fmt.Errorf("unsafe credential directory: %w", err)
	}
	dir, err := os.MkdirTemp(root, "r2-")
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			if err := os.RemoveAll(dir); err != nil {
				result = errors.Join(result, errors.New("could not remove staged credential directory; inspect protected storage before retrying"))
			}
		}
	}()
	for name, value := range map[string]string{"aws": "[relay-coordinator]\naws_access_key_id = " + access + "\naws_secret_access_key = " + secret + "\n", "parent": parentSecret + "\n", "control": control + "\n"} {
		f, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return errors.New("cannot stage protected credential file")
		}
		_, writeErr := f.WriteString(value)
		syncErr := f.Sync()
		closeErr := f.Close()
		if writeErr != nil || syncErr != nil || closeErr != nil {
			return errors.New("cannot save protected credential file")
		}
	}
	old := w.d
	w.d.Storage, w.d.Credentials, w.d.R2Parent, w.d.R2Control = v, filepath.Join(dir, "aws"), filepath.Join(dir, "parent"), filepath.Join(dir, "control")
	w.d.SessionCredentials = mode == "session"
	if err := w.save(); err != nil {
		w.d = old
		return err
	}
	committed = true
	if mode == "session" {
		w.sessionCredentialDirs = append(w.sessionCredentialDirs, dir)
	}
	fmt.Fprintln(w.output, "Settings saved. Next: Check storage. Old credential files were left untouched; no cloud credentials were revoked.")
	return nil
}

// A session generation must not be orphaned by replacing its only durable
// references. Closing the wizard first runs cleanup; a restart inspects any
// leftovers before another generation can be saved.
func (w *coordinatorWizard) requirePreviousSessionClosed() error {
	if !w.d.SessionCredentials {
		return nil
	}
	for _, path := range []string{w.d.Credentials, w.d.R2Parent, w.d.R2Control} {
		if path == "" {
			continue
		}
		if _, err := os.Lstat(path); err == nil {
			return errors.New("session credentials are still present: save and exit to clean up this session, then reopen before replacing storage settings")
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func (w *coordinatorWizard) cleanupSessionCredentials() error {
	var result error
	for _, dir := range w.sessionCredentialDirs {
		// Only directories freshly allocated by this wizard, never a configured
		// arbitrary path or a parent containing somebody else's credentials.
		if err := removeR2SessionFiles(dir); err != nil {
			result = errors.Join(result, fmt.Errorf("could not remove session credential directory %s", dir))
		}
	}
	if len(w.sessionCredentialDirs) > 0 {
		fmt.Fprintln(w.output, "Session credential cleanup attempted. Re-enter credentials next time. Deletion does not exclude backup/snapshot copies.")
	}
	return result
}

func removeR2SessionFiles(dir string) error {
	for _, name := range []string{"aws", "parent", "control"} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := os.Remove(dir); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (w *coordinatorWizard) inspectPreviousSessionCredentials() error {
	if !w.d.SessionCredentials {
		return nil
	}
	dir := filepath.Dir(w.d.Credentials)
	if w.d.Credentials != filepath.Join(dir, "aws") || w.d.R2Parent != filepath.Join(dir, "parent") || w.d.R2Control != filepath.Join(dir, "control") {
		return errors.New("saved session credential references need manual inspection; nothing removed")
	}
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(w.output, "Previous session credentials are no longer on disk. Set up storage credentials again before cloud operations; the ceremony and existing progress are retained.")
		return nil
	} else if err != nil {
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
	if filepath.Dir(dir) != root || !strings.HasPrefix(filepath.Base(dir), "r2-") {
		return errors.New("session credential directory is outside Relay's protected storage; inspect it manually")
	}
	if err := validateRoleMount(dir, false); err != nil {
		return err
	}
	fmt.Fprintf(w.output, "Previous session files remain at %s, possibly after an interruption. This does not mean they were securely erased. Only aws, parent and control in that directory will be removed; other files are preserved.\n", dir)
	if err := w.confirm("Inspect any interrupted Docker task first, then remove these leftover session credential files", "REMOVE SESSION FILES"); err != nil {
		return err
	}
	if err := removeR2SessionFiles(dir); err != nil {
		return fmt.Errorf("session cleanup incomplete: %w", err)
	}
	fmt.Fprintln(w.output, "Leftover session credential files removed. Re-enter credentials in storage setup; backups and snapshots are not checked.")
	return nil
}
