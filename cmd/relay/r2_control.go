package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/zksecurity/relay/internal/access"
)

const cloudflareAPIBaseURL = "https://api.cloudflare.com/client/v4"

type cloudflareAPIError struct {
	Message string `json:"message"`
}

type cloudflareAPIResponse[T any] struct {
	Success bool                 `json:"success"`
	Result  T                    `json:"result"`
	Errors  []cloudflareAPIError `json:"errors"`
}

type r2ManagedDomain struct {
	BucketID string `json:"bucketId"`
	Domain   string `json:"domain"`
	Enabled  *bool  `json:"enabled"`
}

type r2CustomDomain struct {
	Domain string `json:"domain"`
}

type r2CustomDomains struct {
	Domains *[]r2CustomDomain `json:"domains"`
}

func preflightR2InboxPrivacy(config access.StorageConfig) error {
	token, err := consumeR2Credential(r2ControlTokenEnvironment)
	if err != nil {
		return err
	}
	if token == "" {
		return fmt.Errorf("%s is required to verify that the R2 inbox has no public domains", r2ControlTokenEnvironment)
	}
	if err := os.Unsetenv(r2ControlTokenEnvironment); err != nil {
		return fmt.Errorf("clear %s before storage probes: %w", r2ControlTokenEnvironment, err)
	}
	client := &http.Client{Timeout: 30 * time.Second}
	return checkR2InboxPrivacy(config, token, client, cloudflareAPIBaseURL)
}

func checkR2InboxPrivacy(config access.StorageConfig, token string, client *http.Client, apiBaseURL string) error {
	base := strings.TrimRight(apiBaseURL, "/") + "/accounts/" + url.PathEscape(config.AccountID) +
		"/r2/buckets/" + url.PathEscape(config.InboxBucket) + "/domains"
	managed, err := cloudflareGET[r2ManagedDomain](client, token, base+"/managed")
	if err != nil {
		return fmt.Errorf("verify R2 inbox r2.dev status: %w", err)
	}
	if managed.BucketID == "" || managed.Domain == "" || managed.Enabled == nil {
		return errors.New("verify R2 inbox r2.dev status: Cloudflare API response omitted required fields")
	}
	if *managed.Enabled {
		return fmt.Errorf("private R2 inbox %q has public r2.dev access enabled at %s", config.InboxBucket, managed.Domain)
	}
	custom, err := cloudflareGET[r2CustomDomains](client, token, base+"/custom")
	if err != nil {
		return fmt.Errorf("verify R2 inbox custom domains: %w", err)
	}
	if custom.Domains == nil {
		return errors.New("verify R2 inbox custom domains: Cloudflare API response omitted domains")
	}
	if len(*custom.Domains) != 0 {
		names := make([]string, 0, len(*custom.Domains))
		for _, domain := range *custom.Domains {
			names = append(names, domain.Domain)
		}
		sort.Strings(names)
		return fmt.Errorf("private R2 inbox %q has custom domains attached: %s", config.InboxBucket, strings.Join(names, ", "))
	}
	return nil
}

func cloudflareGET[T any](client *http.Client, token, endpoint string) (T, error) {
	var zero T
	request, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return zero, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return zero, err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return zero, err
	}
	var decoded cloudflareAPIResponse[T]
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return zero, fmt.Errorf("decode Cloudflare API response: %w", err)
	}
	if response.StatusCode != http.StatusOK || !decoded.Success {
		message := response.Status
		if len(decoded.Errors) != 0 && decoded.Errors[0].Message != "" {
			message = decoded.Errors[0].Message
		}
		return zero, errors.New(message)
	}
	return decoded.Result, nil
}
