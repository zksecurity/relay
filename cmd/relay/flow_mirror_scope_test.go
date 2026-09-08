package main

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/zksecurity/relay/internal/transcript"
)

func TestMirrorCoverageRequiresEveryHeadAndExactRecord(t *testing.T) {
	chain := transcript.Chain{CeremonyID: "ceremony", Phase: "phase1", Records: []transcript.ChainRecord{{Index: 1, RecordID: "head1"}, {Index: 2, RecordID: "head2"}}}
	pair := func(index int, head string) []flowAttempt {
		scope := flowReceiptScope{CeremonyID: "ceremony", Phase: "phase1", Index: index, Head: head, Digest: "digest-" + head, SignatureDigest: "signature-" + head}
		scope.Mirror.ID = "mirror"
		return []flowAttempt{{Task: "sign-receipt", Stage: "phase1", Status: "succeeded", ReceiptScope: &scope}, {Task: "submit", Stage: "phase1", Status: "succeeded", ReceiptScope: &scope}}
	}
	check := func(*flowAttempt) error { return nil }
	attempts := pair(1, "head1")
	if err := mirrorCoverage(chain, attempts, check); err == nil || !strings.Contains(err.Error(), "contribution 2") {
		t.Fatal("one receipt completed all heads", err)
	}
	attempts = append(attempts, pair(2, "head2")...)
	if err := mirrorCoverage(chain, attempts, check); err != nil {
		t.Fatal(err)
	}
	original := *attempts[3].ReceiptScope
	changed := original
	changed.Digest = "different"
	attempts[3].ReceiptScope = &changed
	if err := mirrorCoverage(chain, attempts, check); err == nil {
		t.Fatal("different signed/uploaded records matched")
	}
	attempts[3].ReceiptScope = &original
	changedSignature := original
	changedSignature.SignatureDigest = "different-signature"
	attempts[3].ReceiptScope = &changedSignature
	if err := mirrorCoverage(chain, attempts, check); err == nil {
		t.Fatal("different signed/uploaded signatures matched")
	}
	attempts[3].ReceiptScope = &original
	if err := mirrorCoverage(chain, attempts, func(a *flowAttempt) error {
		if a.Task == "submit" {
			return errors.New("modified")
		}
		return nil
	}); err == nil {
		t.Fatal("modified receipt counted")
	}
	raw, err := json.Marshal(attempts)
	if err != nil {
		t.Fatal(err)
	}
	var restored []flowAttempt
	if err := json.Unmarshal(raw, &restored); err != nil {
		t.Fatal(err)
	}
	if err := mirrorCoverage(chain, restored, check); err != nil {
		t.Fatal("scope did not survive restart", err)
	}
}
