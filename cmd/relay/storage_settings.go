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
	w.d.Storage, w.d.Credentials = v, credential
	return w.save()
}
