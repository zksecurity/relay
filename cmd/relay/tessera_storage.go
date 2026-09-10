package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const tesseraConnectionSchema = "tessera-cli-connection-v1"
const tesseraProviderPrefix = "[tessera]\ncredential_process = /usr/local/bin/relay tessera storage-credentials --connection /credentials/aws\n# tessera_connection_v1="

var connectionUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

type tesseraStorageConnection struct {
	Schema                 string                     `json:"schema"`
	ConnectionID           string                     `json:"connection_id"`
	CeremonyID             string                     `json:"ceremony_id"`
	Origin                 string                     `json:"origin"`
	ExpiresAt              string                     `json:"expires_at"`
	CoordinatorFingerprint string                     `json:"coordinator_fingerprint"`
	Token                  string                     `json:"token"`
	Settings               coordinatorStorageSettings `json:"settings"`
}
type tesseraAWSCredentials struct {
	Version         int    `json:"Version"`
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	SessionToken    string `json:"SessionToken"`
	Expiration      string `json:"Expiration"`
}

func (c tesseraStorageConnection) validate() error {
	u, err := url.Parse(c.Origin)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("connection requires a plain HTTPS website origin")
	}
	exp, err := time.Parse(time.RFC3339Nano, c.ExpiresAt)
	if err != nil || !exp.After(time.Now()) || exp.After(time.Now().Add(31*24*time.Hour)) {
		return errors.New("connection expired or has an invalid lifetime; download a new connection from Tessera")
	}
	if c.Schema != tesseraConnectionSchema || !connectionUUID.MatchString(c.ConnectionID) || !connectionUUID.MatchString(c.CeremonyID) || !regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`).MatchString(c.Token) || !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(c.CoordinatorFingerprint) {
		return errors.New("invalid Tessera connection file")
	}
	if c.Settings.Settings["provider"] != "aws" || c.Settings.Settings["profile"] != "tessera" || c.Settings.Settings["issuer-profile"] != "tessera" {
		return errors.New("connection must use managed AWS profiles")
	}
	_, err = c.Settings.infrastructure()
	return err
}
func tesseraConnectionRequest(c tesseraStorageConnection, client *http.Client) (tesseraAWSCredentials, error) {
	var result tesseraAWSCredentials
	if err := c.validate(); err != nil {
		return result, err
	}
	req, err := http.NewRequest(http.MethodPost, strings.TrimSuffix(c.Origin, "/")+"/api/v1/cli-storage/"+c.ConnectionID+"/credentials", strings.NewReader("{}"))
	if err != nil {
		return result, errors.New("invalid connection request")
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return result, errors.New("cannot reach Tessera to renew storage access; check your connection and try again")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == 401 || resp.StatusCode == 403 || resp.StatusCode == 409 {
			return result, errors.New("Tessera connection expired, was disconnected, or no longer matches this ceremony; review access on the website and reconnect")
		}
		return result, errors.New("Tessera could not renew AWS access; ask the site administrator to check its AWS login and retry")
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if err != nil || len(raw) > 65536 {
		return result, errors.New("invalid credential response")
	}
	var response struct {
		Data struct {
			Credentials tesseraAWSCredentials `json:"credentials"`
		} `json:"data"`
	}
	if err = json.Unmarshal(raw, &response); err != nil {
		return result, errors.New("invalid credential response")
	}
	result = response.Data.Credentials
	exp, err := time.Parse(time.RFC3339Nano, result.Expiration)
	if err != nil || exp.Before(time.Now().Add(time.Minute)) || exp.After(time.Now().Add(3700*time.Second)) || result.Version != 1 || !regexp.MustCompile(`^ASIA[A-Z0-9]{16}$`).MatchString(result.AccessKeyID) || !regexp.MustCompile(`^[A-Za-z0-9/+=]{40}$`).MatchString(result.SecretAccessKey) || len(result.SessionToken) < 16 || len(result.SessionToken) > 10000 || !regexp.MustCompile(`^[A-Za-z0-9/+=]+$`).MatchString(result.SessionToken) {
		return tesseraAWSCredentials{}, errors.New("Tessera returned invalid temporary credentials")
	}
	return result, nil
}
func tesseraStorageClient() *http.Client {
	return &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirects are not allowed") }}
}
func connectionProfile(c tesseraStorageConnection) ([]byte, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	return []byte(tesseraProviderPrefix + base64.RawURLEncoding.EncodeToString(raw) + "\n"), nil
}
func readConnectionProfile(path string) (tesseraStorageConnection, error) {
	var c tesseraStorageConnection
	raw, err := readTesseraRegularFile(path, 65536, true)
	if err != nil {
		return c, errors.New("connection credentials must be a private regular file (chmod 600)")
	}
	if !bytes.HasPrefix(raw, []byte(tesseraProviderPrefix)) {
		return c, errors.New("not a Tessera automatic credentials profile")
	}
	encoded := strings.TrimSuffix(string(raw[len(tesseraProviderPrefix):]), "\n")
	b, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return c, errors.New("invalid connection profile")
	}
	if err = tesseraDecodeExact(b, &c); err != nil {
		return c, errors.New("invalid connection profile")
	}
	return c, c.validate()
}
func runTesseraStorageCredentials(args []string) error {
	f := flag.NewFlagSet("tessera storage-credentials", flag.ContinueOnError)
	path := f.String("connection", "", "private automatic credentials profile")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || !filepath.IsAbs(*path) {
		return errors.New("--connection must be an absolute private file path")
	}
	c, err := readConnectionProfile(*path)
	if err != nil {
		return err
	}
	result, err := tesseraConnectionRequest(c, tesseraStorageClient())
	if err != nil {
		return err
	}
	// stdout belongs only to AWS credential_process; never print connection secrets.
	return json.NewEncoder(os.Stdout).Encode(result)
}
func (c tesseraStorageConnection) matchesDraft(d coordinatorDraft) error {
	if d.TesseraSetup == nil {
		return errors.New("open the setup downloaded from Tessera first")
	}
	if c.CeremonyID != d.TesseraSetup.ID || c.CoordinatorFingerprint != d.Identities.Coordinator.Fingerprint {
		return errors.New("connection belongs to a different ceremony or coordinator key")
	}
	expected := d.TesseraSetup.Plan.Storage
	s := c.Settings.Settings
	if s["region"] != expected.Region || s["published-bucket"] != expected.PublishedBucket || s["inbox-bucket"] != expected.InboxBucket || s["published-base-url"] != expected.PublicBaseURL {
		return errors.New("connection storage differs from the imported setup")
	}
	return nil
}
func (w *coordinatorWizard) connectTesseraStorage() error {
	if w.d.TesseraSetup == nil {
		return errors.New("open the setup downloaded from Tessera before connecting storage")
	}
	path, err := w.required("Private CLI connection JSON downloaded from Tessera, absolute path", "")
	if err != nil {
		return err
	}
	if !filepath.IsAbs(path) {
		return errors.New("absolute connection-file path required")
	}
	raw, err := readTesseraRegularFile(path, 65536, true)
	if err != nil {
		return errors.New("protect the downloaded connection file with chmod 600, then retry")
	}
	var c tesseraStorageConnection
	if err = tesseraDecodeExact(raw, &c); err != nil {
		return errors.New("choose the CLI connection JSON, not a setup JSON or credentials INI")
	}
	if err = c.validate(); err != nil {
		return err
	}
	if err = c.matchesDraft(w.d); err != nil {
		return err
	}
	destination := w.d.Credentials
	var previous []byte
	if destination != "" {
		previous, err = readTesseraRegularFile(destination, 65536, true)
		if err != nil {
			return errors.New("existing credentials file is unavailable; preserve it and resolve its permissions")
		}
		if !bytes.HasPrefix(previous, []byte(tesseraProviderPrefix)) && !(bytes.HasPrefix(previous, []byte("# Temporary Tessera access.")) && bytes.Count(previous, []byte("[")) == 1 && bytes.Contains(previous, []byte("[tessera]"))) {
			return errors.New("existing credentials are not a dedicated Tessera file; do not overwrite another AWS profile")
		}
	} else {
		directory := filepath.Join(filepath.Dir(w.d.Keys), "storage-access")
		if err = os.MkdirAll(directory, 0700); err != nil {
			return err
		}
		if err = validateRoleMount(directory, false); err != nil {
			return err
		}
		destination = filepath.Join(directory, "aws")
		if _, err = os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
			existing, readErr := readConnectionProfile(destination)
			if readErr != nil || existing.ConnectionID != c.ConnectionID || existing.Token != c.Token {
				return errors.New("storage-access/aws already exists with different data; preserve and review it before retrying")
			}
			previous, err = readTesseraRegularFile(destination, 65536, true)
			if err != nil {
				return err
			}
		}
	}
	fmt.Fprintf(w.output, "Website: %s\nCeremony: %s\nCoordinator fingerprint: %s\nConnection expires: %s\nPrivate credentials profile: %s\n", c.Origin, c.CeremonyID, c.CoordinatorFingerprint, c.ExpiresAt, destination)
	if err = w.confirm("Connect this CLI to Tessera for automatic storage renewal. This replaces only the dedicated credentials profile; it does not change your signing key. Disconnect on the website to stop renewal", "CONNECT TESSERA"); err != nil {
		return err
	}
	if _, err = tesseraConnectionRequest(c, tesseraStorageClient()); err != nil {
		return err
	}
	profile, err := connectionProfile(c)
	if err != nil {
		return err
	}
	if previous == nil {
		f, e := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return e
		}
		_, err = f.Write(profile)
		err = errors.Join(err, f.Close())
		if err != nil {
			return err
		}
	} else {
		current, e := readTesseraRegularFile(destination, 65536, true)
		if e != nil || !bytes.Equal(current, previous) {
			return errors.New("credentials changed during review; nothing replaced")
		}
		temp, e := os.CreateTemp(filepath.Dir(destination), ".tessera-connection-*")
		if e != nil {
			return e
		}
		defer os.Remove(temp.Name())
		_, err = temp.Write(profile)
		err = errors.Join(err, temp.Close())
		if err != nil {
			return err
		}
		if err = os.Rename(temp.Name(), destination); err != nil {
			return err
		}
	}
	w.d.Storage, w.d.Credentials = c.Settings.Settings, destination
	w.d.R2Parent, w.d.R2Control, w.d.SessionCredentials = "", "", false
	if err = w.save(); err != nil {
		return err
	}
	w.message(toneSuccess, "Tessera connected. AWS access renews automatically when needed. Keep this role folder; remove the original downloaded connection file when you no longer need it.\n")
	return nil
}
