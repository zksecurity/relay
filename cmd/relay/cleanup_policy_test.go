package main

import (
	"testing"

	"github.com/zksecurity/relay/internal/access"
)

func TestRemovedHostWipeInterfacesRejected(t *testing.T) {
	if err := runParticipant([]string{"attest-host-wipe"}); err == nil {
		t.Fatal("removed participant command accepted")
	}
	if _, err := access.Prefix("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "host-wipe", "participant-01"); err == nil {
		t.Fatal("removed grant role accepted")
	}
}
