package main

// These names come from the authenticated proof-tool circuit registry. Test
// circuits cannot produce ownership proofs even if a production-mode ceremony
// using them receives GO for its exact signed circuit.
func ceremonyTestCircuit(keyVersion string) bool {
	return keyVersion == "rehearsal-tiny-v1" || keyVersion == "rehearsal-k11-v1"
}

func supportedCeremonyCircuit(keyVersion string) bool {
	return keyVersion == "ownership-destination-v3" || ceremonyTestCircuit(keyVersion)
}
