package transcript

import (
	"fmt"
	"regexp"
)

// publishable enumerates every logical artifact name a ceremony transcript may
// contain. It is an allowlist, not a denylist: a name that matches nothing here
// is refused.
//
// The direction matters. A denylist has to anticipate every shape a secret can
// take, and the cost of missing one is a signing key in a public bucket. An
// allowlist fails the other way: a legitimate artifact this list has not
// learned about yet is refused loudly, which is a bug report rather than a
// disclosure.
//
// Deliberately absent: anything under a private control directory, participant
// candidate working directories, and every `*.private.hex` key file. Those live
// outside the published transcript and have no logical name here.
var publishable = []*regexp.Regexp{
	// Ceremony root.
	regexp.MustCompile(`^ceremony\.json$`),
	regexp.MustCompile(`^ceremony\.sig$`),
	regexp.MustCompile(`^coordinator-public-key\.hex$`),
	regexp.MustCompile(`^ownership-destination\.ccs$`),

	// Per phase: genesis, the signed accepted chain at each index, and the
	// accepted contribution evidence.
	regexp.MustCompile(`^phase[12]/genesis\.bin$`),
	regexp.MustCompile(`^phase[12]/chain-\d{4}\.json$`),
	regexp.MustCompile(`^phase[12]/chain-\d{4}\.sig$`),
	regexp.MustCompile(`^phase[12]/contributions/\d{4}/contribution\.bin$`),
	regexp.MustCompile(`^phase[12]/contributions/\d{4}/attestation\.json$`),
	regexp.MustCompile(`^phase[12]/contributions/\d{4}/attestation\.sig$`),
	regexp.MustCompile(`^phase[12]/contributions/\d{4}/erasure\.json$`),
	regexp.MustCompile(`^phase[12]/contributions/\d{4}/erasure\.sig$`),
	regexp.MustCompile(`^phase[12]/contributions/\d{4}/verification\.json$`),

	// Phase closure, the offline beacon response that seals it, and the seal.
	regexp.MustCompile(`^phase[12]/closure/record\.json$`),
	regexp.MustCompile(`^phase[12]/closure/record\.sig$`),
	regexp.MustCompile(`^phase[12]/beacon/raw-response\.bin$`),
	regexp.MustCompile(`^phase[12]/beacon/record\.json$`),
	regexp.MustCompile(`^phase[12]/beacon/record\.sig$`),
	regexp.MustCompile(`^phase1/sealed/commons\.bin$`),
	regexp.MustCompile(`^phase1/sealed/seal\.json$`),
	regexp.MustCompile(`^phase1/sealed/seal\.sig$`),
}

// CheckPublishable reports whether a logical artifact name may leave the local
// transcript. It runs in addition to ValidateName, which handles path shape;
// this decides whether a well-formed name is one the ceremony actually
// publishes.
func CheckPublishable(name string) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	for _, pattern := range publishable {
		if pattern.MatchString(name) {
			return nil
		}
	}
	return fmt.Errorf("artifact %q is not a publishable ceremony artifact", name)
}
