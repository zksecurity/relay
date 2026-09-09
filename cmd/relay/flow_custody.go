package main

// Custody actions happen in the key-owning offline profile. Public files are
// transferred separately; no action asserts that a physical air gap was used.
func custodyPrepareFlow(phase, direction string) flowTask {
	task := withFields(flowProof("prepare-"+direction+"-handoff", "Prepare "+direction+" custody handoff", "Use the current chain before acceptance. Outbound runs before contribution; return runs after cleanup. The tool derives the turn and file hashes and records the actual current time; never backdate a missing handoff.", "ops", "prepare-handoff"), ff("transcript-root", "Public transcript at this station", "/work/ceremony/public"), ff("chain", "Current signed chain before this turn", "/work/ceremony/public/"+phase+"/chain-0000.json"), ff("chain-signature", "Matching current chain signature", "/work/ceremony/public/"+phase+"/chain-0000.sig"), ft("participant-id", "Next scheduled participant ID", ""), ft("direction", "Handoff direction", direction), ff("out-dir", "Fresh signing packet for this turn", "/work/custody/"+phase+"-"+direction))
	if direction == "return" {
		task.Fields = append(task.Fields, ff("candidate-dir", "Retained completed public candidate directory", "/work/candidate"))
	}
	task.Offline = true
	return task
}
func custodySignFlow(phase, direction, kind string) flowTask {
	base := "/work/custody/" + phase + "-" + direction
	if kind == "receipt" {
		base += "-receipt"
	}
	task := withFields(flowProof("sign-"+direction+"-"+kind, "Review and sign "+direction+" "+kind, "Review the exact displayed bytes and their custody claims. Keep this signature with the exact packet. Signing authenticates the owner; it does not prove physical transfer or erasure.", "ops", "sign", "--reviewed"), ft("record-type", "Record type", kind), ff("record", "Canonical record", base+"/canonical.json"), ff("signing-key", "Your own signing key", "/keys/signing.hex"), ff("out", "Fresh detached signature", base+"/record.sig"))
	task.Offline = true
	return task
}
func custodyReceiptFlow(phase, direction string) flowTask {
	base := "/work/custody/" + phase + "-" + direction
	task := withFields(flowProof("prepare-"+direction+"-receipt", "Verify received files and prepare "+direction+" receipt", "First receive the sender's signed handoff and every named public file into their logical paths under the received-files root. The tool verifies the sender and all retained bytes before recording the current receipt time.", "ops", "prepare-receipt"), ff("transcript-root", "Root containing received public files", "/work/ceremony/public"), ff("handoff", "Received canonical handoff", base+"/canonical.json"), ff("handoff-signature", "Sender signature", base+"/record.sig"), ff("sender-public-key-file", "Independently authenticated sender public key", "/trust/sender-public-key.hex"), ff("out-dir", "Fresh receiver signing packet", base+"-receipt"))
	task.Offline = true
	return task
}
func custodyVerifyFlow(phase, direction string) flowTask {
	base := "/work/custody/" + phase + "-" + direction
	task := withFields(flowProof("verify-"+direction+"-receipt", "Verify the recipient's signed "+direction+" receipt", "Retain this exact signature and handoff. Outbound receipt must precede computation; return receipt must precede acceptance.", "ops", "verify"), ft("record-type", "Record type", "receipt"), ff("record", "Recipient's canonical receipt", base+"-receipt/canonical.json"), ff("signature", "Recipient signature", base+"-receipt/record.sig"), ff("related-record", "Exact original handoff", base+"/canonical.json"), ff("signer-public-key-file", "Authenticated recipient public key", "/trust/recipient-public-key.hex"))
	task.Offline = true
	return task
}
