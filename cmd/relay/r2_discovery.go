package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os/exec"
	"time"
)

type r2Account struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
type r2BucketList struct {
	Buckets []struct {
		Name string `json:"name"`
	} `json:"buckets"`
}

// Output is captured and parsed, never printed: auth token output is a secret.
func wranglerIdentity() ([]r2Account, string, error) {
	binary, err := exec.LookPath("wrangler")
	if err != nil {
		return nil, "", errors.New("Wrangler is not installed; choose manual settings or administrator import")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	raw, err := exec.CommandContext(ctx, binary, "whoami", "--json").Output()
	if err != nil {
		return nil, "", errors.New("Wrangler login unavailable; run wrangler login yourself or choose manual settings")
	}
	var identity struct {
		Accounts []r2Account `json:"accounts"`
	}
	if json.Unmarshal(raw, &identity) != nil || len(identity.Accounts) == 0 {
		return nil, "", errors.New("Wrangler did not identify an accessible account")
	}
	raw, err = exec.CommandContext(ctx, binary, "auth", "token", "--json").Output()
	if err != nil {
		return nil, "", errors.New("Wrangler could not supply its current credential; reconnect through wrangler login")
	}
	var credential struct {
		Type  string `json:"type"`
		Token string `json:"token"`
	}
	if json.Unmarshal(raw, &credential) != nil || credential.Type != "oauth" || credential.Token == "" {
		return nil, "", errors.New("expected an authorized Wrangler OAuth login")
	}
	return identity.Accounts, credential.Token, nil
}

func (w *coordinatorWizard) discoverR2() (map[string]string, string, error) {
	fmt.Fprintln(w.output, "Read existing accounts, buckets and public domains using your authorized Wrangler login. Select every resource explicitly. This does not create buckets or change permissions.")
	accounts, token, err := wranglerIdentity()
	if err != nil {
		return nil, "", err
	}
	choices := []setupChoice{}
	for _, account := range accounts {
		if !validR2Hex(account.ID, 16) {
			return nil, "", errors.New("invalid account identifier returned by Wrangler")
		}
		choices = append(choices, setupChoice{account.ID, fmt.Sprintf("%q (%s)", account.Name, account.ID)})
	}
	account, err := w.choose("Cloudflare account", "", choices)
	if err != nil {
		return nil, "", err
	}
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
	base := cloudflareAPIBaseURL + "/accounts/" + account + "/r2/buckets"
	buckets, err := cloudflareGET[r2BucketList](client, token, base)
	if err != nil {
		return nil, "", errors.New("could not list R2 buckets; check login permissions or enter administrator-provided settings manually")
	}
	choices = nil
	for _, bucket := range buckets.Buckets {
		choices = append(choices, setupChoice{bucket.Name, fmt.Sprintf("%q", bucket.Name)})
	}
	if len(choices) < 2 {
		return nil, "", errors.New("two distinct existing buckets are needed; create a public transcript bucket and private inbox in the Cloudflare dashboard, then return")
	}
	published, err := w.choose("Public transcript bucket (available results)", "", choices)
	if err != nil {
		return nil, "", err
	}
	inboxChoices := []setupChoice{}
	for _, c := range choices {
		if c.value != published {
			inboxChoices = append(inboxChoices, c)
		}
	}
	inbox, err := w.choose("Private role-submission inbox", "", inboxChoices)
	if err != nil {
		return nil, "", err
	}
	managed, err := cloudflareGET[r2ManagedDomain](client, token, base+"/"+url.PathEscape(published)+"/domains/managed")
	if err != nil {
		return nil, "", errors.New("could not inspect the transcript bucket's public address; enter reviewed settings manually")
	}
	custom, err := cloudflareGET[r2CustomDomains](client, token, base+"/"+url.PathEscape(published)+"/domains/custom")
	if err != nil || custom.Domains == nil {
		return nil, "", errors.New("could not inspect custom public domains")
	}
	origins := []setupChoice{}
	if managed.Enabled != nil && *managed.Enabled && managed.Domain != "" {
		origins = append(origins, setupChoice{"https://" + managed.Domain, "https://" + managed.Domain})
	}
	for _, d := range *custom.Domains {
		origins = append(origins, setupChoice{"https://" + d.Domain, fmt.Sprintf("https://%s (public-read check still required)", d.Domain)})
	}
	if len(origins) == 0 {
		return nil, "", errors.New("no public transcript address configured; enable the chosen transcript bucket's public address in Cloudflare, never the inbox's")
	}
	origin, err := w.choose("Public transcript address to verify", "", origins)
	if err != nil {
		return nil, "", err
	}
	return map[string]string{"account-id": account, "published-bucket": published, "inbox-bucket": inbox, "published-base-url": origin}, token, nil
}
