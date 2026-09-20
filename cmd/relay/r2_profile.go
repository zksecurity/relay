package main

import (
	"bufio"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

func parseR2CoordinatorProfiles(raw []byte) (map[string][2]string, error) {
	profiles := map[string][2]string{}
	seen := map[string]map[string]bool{}
	section := ""
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			if section == "" || seen[section] != nil {
				return nil, errors.New("credential file has empty or duplicate profile sections")
			}
			seen[section] = map[string]bool{}
			continue
		}
		if section == "" {
			return nil, errors.New("credential file requires named profile sections")
		}
		key, value, ok := strings.Cut(line, "=")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if !ok || seen[section][key] {
			return nil, errors.New("malformed or duplicate credential fields")
		}
		seen[section][key] = true
		pair := profiles[section]
		switch key {
		case "aws_access_key_id":
			pair[0] = value
		case "aws_secret_access_key":
			pair[1] = value
		}
		profiles[section] = pair
	}
	if scanner.Err() != nil {
		return nil, errors.New("cannot parse protected credential file")
	}
	for name, pair := range profiles {
		if !validR2Hex(pair[0], 16) || !validR2Hex(pair[1], 32) || len(seen[name]) != 2 {
			delete(profiles, name)
		}
	}
	return profiles, nil
}

func (w *coordinatorWizard) coordinatorR2Credential() (string, string, error) {
	choice, err := w.choose("Coordinator object-storage access", "", []setupChoice{{"existing", "Use one profile from my existing protected credentials file"}, {"new", "Enter coordinator access key and secret"}})
	if err != nil {
		return "", "", err
	}
	if choice == "new" {
		id, err := w.credential("Coordinator Access Key ID (published + inbox buckets)")
		if err != nil {
			return "", "", err
		}
		secret, err := w.credential("Coordinator Secret Access Key")
		return id, secret, err
	}
	return w.existingR2Credential()
}

func (w *coordinatorWizard) inboxR2Credential() (string, string, error) {
	choice, err := w.choose("Inbox-only object-storage access", "", []setupChoice{
		{"existing", "Use one named profile from a protected AWS-format credentials file"},
		{"new", "Enter Access Key ID and Secret Access Key separately (hidden paste or single-value files)"},
		{"cancel", "Cancel"},
	})
	if err != nil {
		return "", "", err
	}
	switch choice {
	case "existing":
		return w.existingR2Credential()
	case "new":
		id, err := w.credential("Inbox-only credential — Access Key ID")
		if err != nil {
			return "", "", err
		}
		secret, err := w.credential("Inbox-only credential — Secret Access Key")
		return id, secret, err
	default:
		return "", "", errors.New("cancelled; no credentials saved")
	}
}

// Both roles select a single key pair without retaining the source file or
// changing the draft. Dedicated copies are staged only after confirmation.
func (w *coordinatorWizard) existingR2Credential() (string, string, error) {
	path := w.d.Credentials
	if path == "" {
		if home, err := os.UserHomeDir(); err == nil {
			path = filepath.Join(home, ".aws", "credentials")
		}
	}
	path, err := w.required("Protected AWS-format credentials file", path)
	if err != nil {
		return "", "", err
	}
	raw, err := readProtectedCredentialBytes(path, 1<<20)
	if err != nil {
		return "", "", err
	}
	profiles, err := parseR2CoordinatorProfiles(raw)
	if err != nil {
		return "", "", err
	}
	choices := []setupChoice{}
	for _, name := range slices.Sorted(maps.Keys(profiles)) {
		choices = append(choices, setupChoice{name, fmt.Sprintf("%q", name)})
	}
	if len(choices) == 0 {
		return "", "", errors.New("no supported R2 key-pair profile; use explicit credential entry (session/SSO/credential-process profiles are not imported)")
	}
	selected, err := w.choose("Copy ONLY the selected profile into Relay's dedicated credential set", "", choices)
	if err != nil {
		return "", "", err
	}
	pair := profiles[selected]
	return pair[0], pair[1], nil
}
