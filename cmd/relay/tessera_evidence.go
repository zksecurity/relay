package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/zksecurity/relay/internal/access"
)

const tesseraRoleConnectionSchema = "tessera-role-connection-v1"

type tesseraRoleConnection struct {
	Schema       string `json:"schema"`
	ConnectionID string `json:"connection_id"`
	CeremonyID   string `json:"ceremony_id"`
	ProtocolID   string `json:"protocol_id"`
	AssignmentID string `json:"assignment_id"`
	Origin       string `json:"origin"`
	ExpiresAt    string `json:"expires_at"`
	Role         string `json:"role"`
	IdentityID   string `json:"identity_id"`
	Token        string `json:"token"`
}

func loadTesseraRoleConnection(path string) (tesseraRoleConnection, error) {
	var c tesseraRoleConnection
	raw, err := readTesseraRegularFile(path, 65536, true)
	if err != nil {
		return c, errors.New("role connection must be a private regular file (chmod 600)")
	}
	if err = tesseraDecodeExact(raw, &c); err != nil {
		return c, errors.New("invalid Tessera role connection file")
	}
	u, err := url.Parse(c.Origin)
	expires, timeErr := time.Parse(time.RFC3339Nano, c.ExpiresAt)
	validRole := c.Role == access.RoleParticipant || c.Role == access.RoleWitness || c.Role == access.RoleMirror || c.Role == access.RoleAuditor || c.Role == access.RoleRelease
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || timeErr != nil || !expires.After(time.Now()) || expires.After(time.Now().Add(31*24*time.Hour)) || c.Schema != tesseraRoleConnectionSchema || !connectionUUID.MatchString(c.ConnectionID) || !connectionUUID.MatchString(c.CeremonyID) || !connectionUUID.MatchString(c.AssignmentID) || !tesseraHash.MatchString(c.ProtocolID) || !validRole || !tesseraID.MatchString(c.IdentityID) || !regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`).MatchString(c.Token) {
		return c, errors.New("invalid or expired Tessera role connection")
	}
	return c, nil
}

func tesseraRoleRequest(c tesseraRoleConnection, action string, body any, target any) error {
	return tesseraRoleRequestWithClient(c, action, body, target, tesseraStorageClient())
}

func tesseraRoleRequestWithClient(c tesseraRoleConnection, action string, body any, target any, client *http.Client) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, strings.TrimSuffix(c.Origin, "/")+"/api/v1/cli-evidence/"+c.ConnectionID+"/"+action, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		if action == "grant" {
			return errors.New("cannot reach Tessera to obtain upload access; check the connection and try again")
		}
		return errors.New("the upload succeeded, but Tessera could not be reached; preserve the manifest key and report it on the website")
	}
	defer resp.Body.Close()
	response, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if err != nil || len(response) > 65536 {
		return errors.New("invalid Tessera response")
	}
	if resp.StatusCode != http.StatusOK {
		if action == "grant" {
			return fmt.Errorf("Tessera did not issue upload access (%s); sign in and review this role connection", resp.Status)
		}
		return fmt.Errorf("Tessera rejected %s (%s); preserve the manifest key and report it on the website", strings.ReplaceAll(action, "-", " "), resp.Status)
	}
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err = json.Unmarshal(response, &envelope); err != nil {
		return errors.New("invalid Tessera response")
	}
	if target != nil && json.Unmarshal(envelope.Data, target) != nil {
		return errors.New("invalid Tessera response")
	}
	return nil
}

func tesseraGrant(connectionPath string) (access.Grant, tesseraRoleConnection, error) {
	c, err := loadTesseraRoleConnection(connectionPath)
	if err != nil {
		return access.Grant{}, c, err
	}
	var response struct {
		Grant access.Grant `json:"grant"`
	}
	if err = tesseraRoleRequest(c, "grant", map[string]any{}, &response); err != nil {
		return access.Grant{}, c, err
	}
	if err = response.Grant.Validate(); err != nil {
		return access.Grant{}, c, fmt.Errorf("Tessera returned invalid upload grant: %w", err)
	}
	if response.Grant.CeremonyID != c.ProtocolID || response.Grant.Role != c.Role || response.Grant.IdentityID != c.IdentityID {
		return access.Grant{}, c, errors.New("Tessera grant does not match this role connection")
	}
	return response.Grant, c, nil
}

func loadUploadAccess(path string) (access.Grant, *tesseraRoleConnection, error) {
	raw, err := readTesseraRegularFile(path, 65536, true)
	if err != nil {
		return access.Grant{}, nil, err
	}
	var header struct {
		Schema string `json:"schema"`
	}
	if json.Unmarshal(raw, &header) != nil {
		return access.Grant{}, nil, errors.New("upload access file is not valid JSON")
	}
	if header.Schema == tesseraRoleConnectionSchema {
		grant, c, err := tesseraGrant(path)
		return grant, &c, err
	}
	grant, err := loadGrant(path)
	return grant, nil, err
}

func reportTesseraManifest(c *tesseraRoleConnection, key, attempt, phase string, index int) error {
	if c == nil {
		return nil
	}
	body := map[string]any{"manifest_key": key, "attempt_id": attempt}
	if c.Role == access.RoleParticipant {
		body["phase"] = phase
		body["index"] = index
	}
	if err := tesseraRoleRequest(*c, "submissions", body, &struct {
		Submission json.RawMessage `json:"submission"`
	}{}); err != nil {
		return err
	}
	fmt.Println("Tessera notified: Evidence received — verification needed.")
	return nil
}
