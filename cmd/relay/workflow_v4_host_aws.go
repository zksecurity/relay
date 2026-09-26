package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/zksecurity/relay/internal/access"
	"github.com/zksecurity/relay/internal/store"
)

// Host-side publication and decision transport use the same reviewed AWS
// login binding as coordinator containers. The ceremony's relay-coordinator
// name exists inside those containers, but need not exist in ~/.aws on the host.
func workflowV4BoundHostAWS(online guidedProfile, config access.StorageConfig, bucket string) (store.Client, error) {
	client := store.Client{Region: config.Region, Endpoint: config.Endpoint, Bucket: bucket}
	if online.Credentials == "" {
		return client, errors.New("coordinator AWS credential binding is missing")
	}
	binding, err := readAWSLoginBinding(online.Credentials)
	if err != nil {
		return client, err
	}
	if binding == nil {
		// Earlier installations may retain an isolated INI file rather than a
		// renewable-login descriptor. Never look up an unrelated host profile.
		client.Profile = config.CoordinatorProfile
		client.CredentialsFile = online.Credentials
		return client, nil
	}
	if binding.Region != config.Region {
		return client, errors.New("AWS login region differs from the frozen storage destination")
	}
	client.Binary = binding.Binary
	var cached awsProcessCredentials
	client.CredentialProvider = func(ctx context.Context) (*store.Credentials, error) {
		refresh := cached.Expiration == ""
		if !refresh {
			expiry, err := time.Parse(time.RFC3339, cached.Expiration)
			refresh = err != nil || time.Until(expiry) < 15*time.Minute
		}
		if refresh {
			var err error
			cached, err = refreshAWSLogin(ctx, *binding)
			if err != nil {
				return nil, fmt.Errorf("refresh verified coordinator AWS login: %w", err)
			}
		}
		return &store.Credentials{AccessKeyID: cached.AccessKeyId, SecretAccessKey: cached.SecretAccessKey, SessionToken: cached.SessionToken}, nil
	}
	return client, nil
}
