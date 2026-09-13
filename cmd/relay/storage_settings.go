package main

import (
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
)

type coordinatorStorageSettings struct {
	Schema   string            `json:"schema"`
	Settings map[string]string `json:"settings"`
}

func storageSettingFields(provider string) []string {
	fields := []string{"region", "published-bucket", "published-base-url", "inbox-bucket", "profile"}
	switch provider {
	case "aws":
		return append(fields, "issuer-profile", "grant-role-arn", "grant-role-max-ttl")
	case "r2":
		return append(fields, "account-id", "endpoint", "parent-access-key-id")
	default:
		return nil
	}
}

func (s coordinatorStorageSettings) validate() error {
	fields := storageSettingFields(s.Settings["provider"])
	if s.Schema != "relay-coordinator-storage-settings-v1" || len(fields) == 0 {
		return errors.New("unsupported coordinator storage settings")
	}
	allowed := map[string]bool{"provider": true}
	for _, field := range fields {
		allowed[field] = true
		if strings.TrimSpace(s.Settings[field]) == "" {
			return fmt.Errorf("missing %s", field)
		}
	}
	for key, value := range s.Settings {
		if !allowed[key] || strings.ContainsAny(value, "\x00\r\n") {
			return errors.New("unexpected field or multiline value; this file must not contain credentials, tokens or private keys")
		}
	}
	for _, key := range []string{"published-base-url", "endpoint"} {
		if s.Settings[key] == "" {
			continue
		}
		u, err := url.Parse(s.Settings[key])
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("%s must be an HTTPS URL without credentials or query parameters", key)
		}
	}
	return nil
}

func (w *coordinatorWizard) importStorageSettings() error {
	if err := w.requirePreviousSessionClosed(); err != nil {
		return err
	}
	path, err := w.required("Administrator-provided coordinator storage settings JSON, absolute path", "")
	if err != nil {
		return err
	}
	if !filepath.IsAbs(path) {
		return errors.New("absolute settings-file path required")
	}
	var settings coordinatorStorageSettings
	if err := setupReadJSON(path, &settings); err != nil {
		return err
	}
	if err := settings.validate(); err != nil {
		return err
	}
	v := settings.Settings
	fmt.Fprintf(w.output, "Provider: %s\nPublic transcript address: %s\nPublished bucket: %s\nPrivate inbox bucket: %s\nCredential profile name: %s\n", v["provider"], v["published-base-url"], v["published-bucket"], v["inbox-bucket"], v["profile"])
	fmt.Fprintln(w.output, "This checks the file format, not ownership or cloud permissions. Confirm the administrator and destinations through your agreed channel. Configure storage later performs the actual access checks with your approval.")
	if v["provider"] == "r2" {
		return w.importR2Credentials(settings)
	}
	credential, err := w.required("Your local credentials FILE, delivered separately, absolute path", w.d.Credentials)
	if err != nil {
		return err
	}
	if !filepath.IsAbs(credential) || filepath.Clean(credential) != credential {
		return errors.New("absolute clean credential-file path required")
	}
	if err := w.confirm("Import these non-secret settings without contacting cloud storage", "IMPORT"); err != nil {
		return err
	}
	old := w.d
	w.d.Storage, w.d.Credentials = v, credential
	w.d.R2Parent, w.d.R2Control, w.d.SessionCredentials = "", "", false
	if err := w.save(); err != nil {
		w.d = old
		return err
	}
	return nil
}

func (w *coordinatorWizard) importR2Credentials(settings coordinatorStorageSettings) error {
	if _, err := settings.infrastructure(); err != nil {
		return err
	}
	fmt.Fprintln(w.output, "Reuse three existing protected credential files. Relay will save its own copies; your source files will not be changed or removed. Do not enter secret contents at these path prompts.")
	readPath := func(label, fallback string) (string, error) {
		path, err := w.required(label, fallback)
		if err != nil {
			return "", err
		}
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return "", errors.New("use an absolute clean credential-file path")
		}
		return path, nil
	}
	path, err := readPath("Coordinator access: protected AWS-format credentials FILE", w.d.Credentials)
	if err != nil {
		return err
	}
	raw, err := readProtectedCredentialBytes(path, 1<<20)
	if err != nil {
		return err
	}
	profiles, err := parseR2CoordinatorProfiles(raw)
	if err != nil {
		return err
	}
	pair, ok := profiles[settings.Settings["profile"]]
	if !ok {
		return errors.New("credentials file has no supported R2 key pair for the profile named in these settings")
	}
	path, err = readPath("Inbox-only access: protected parent secret FILE", w.d.R2Parent)
	if err != nil {
		return err
	}
	parent, err := readProtectedCredential(path)
	if err != nil {
		return err
	}
	if !validR2Hex(parent, 32) {
		return errors.New("inbox-only file must contain the R2 secret access key, not an access-key ID or AWS profile")
	}
	if pair[0] == settings.Settings["parent-access-key-id"] {
		return errors.New("use a separate inbox-only credential, not the coordinator credential")
	}
	path, err = readPath("Inbox privacy check: protected control-token FILE", w.d.R2Control)
	if err != nil {
		return err
	}
	control, err := readProtectedCredential(path)
	if err != nil {
		return err
	}
	mode, err := w.choose("Where should Relay keep its credential copies?", "saved", []setupChoice{{"saved", "Save in protected local files"}, {"session", "Use for this session only (temporary disk files)"}, {"cancel", "Cancel"}})
	if err != nil {
		return err
	}
	if mode == "cancel" {
		return errors.New("cancelled; nothing saved")
	}
	fmt.Fprintln(w.output, "File formats checked only. The inbox secret's match to the saved access-key ID, token validity and bucket permissions still require Check storage. Session-only copies use disk; normal exit removes them, but crashes or backups may retain them. Original files remain untouched.")
	if err := w.confirm("Import these settings and save protected credential copies without contacting cloud storage", "IMPORT"); err != nil {
		return err
	}
	return w.saveR2Credentials(settings.Settings, pair[0], pair[1], parent, control, mode)
}
